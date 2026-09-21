// Copyright 2021-2026 Prosopo (UK) Ltd.
// Licensed under the Apache License, Version 2.0

import CryptoKit
import DeviceCheck
import Foundation
import ProsopoAttestShim

/// Manages the App Attest lifecycle: key generation, attestation, and assertion.
///
/// This is the only file that imports `DeviceCheck`. All App Attest operations
/// are routed through this manager.
///
/// Every call into `DCAppAttestService` goes through `AppAttestShim`, an
/// Objective-C exception barrier. DeviceCheck can raise an `NSException`
/// instead of returning an error — observed on iOS 18 as an unrecognized
/// selector inside `DCAppAttestController` — and Swift cannot catch that, so
/// an unguarded call takes the host app down with it.
///
/// On the simulator (where App Attest is unavailable), this falls back to a
/// mock mode that simulates the attestation flow for development purposes.
/// Mock attestations are clearly marked and rejected by production servers.
final class AppAttestManager: @unchecked Sendable {
    private let networkClient: NetworkClient

    /// The current attestation state.
    enum State {
        case uninitialized
        case keyGenerated(keyId: String)
        case attested(keyId: String)
        case unsupported
    }

    /// Guards every mutable field below. The manager is a single shared instance
    /// read and written from many concurrent tasks (one per intercepted request,
    /// plus the background attestation task, `forceReset`, and the WebView
    /// bridge), so unsynchronised access to `state`/`phase`/`lastError` was a data
    /// race. The lock is only ever held around a single field read/write — never
    /// across an `await` — so it cannot deadlock or serialise the async flow.
    private let lock = NSLock()

    private var _state: State = .uninitialized
    private var _phase: String = "idle"
    private var _lastError: String?

    /// The current attestation state. Thread-safe.
    var state: State { lock.withLock { _state } }

    /// Human-readable description of the current attestation phase, for UI debugging.
    /// Updated at each step of `attestIfNeeded`. Thread-safe.
    var phase: String { lock.withLock { _phase } }

    /// Last error message from attestation or assertion, if any. Thread-safe.
    var lastError: String? { lock.withLock { _lastError } }

    private func setState(_ newValue: State) { lock.withLock { _state = newValue } }
    private func setPhase(_ newValue: String) { lock.withLock { _phase = newValue } }
    private func setLastError(_ newValue: String?) { lock.withLock { _lastError = newValue } }

    init(networkClient: NetworkClient) {
        self.networkClient = networkClient
    }

    /// Check if App Attest is supported on this device. Reports `false` if the
    /// support check itself faulted — see `runAttestation` for the case where
    /// that distinction matters.
    var isSupported: Bool {
        AppAttestShim.supportState?.boolValue ?? false
    }

    // MARK: - Backoff

    /// Backoff for Apple's DeviceCheck framework raising an Objective-C
    /// exception. When it faults, its internals have just been unwound by an
    /// exception it was never written to expect, so calling straight back in
    /// re-runs the same OS bug on a framework in an unknown state. We pause,
    /// fail open, and probe again when the window expires.
    ///
    /// Deliberately *not* a permanent kill switch: an unattested device is a
    /// hole in the protection, so the only acceptable resting state is
    /// "attested". We back off, we don't give up.
    ///
    /// Process-wide rather than per-instance: the fault is a property of the OS.
    private static let deviceCheckGate = RetryGate(
        label: "DeviceCheck",
        baseDelay: 30,
        maxDelay: 30 * 60
    )

    /// Backoff for attestation attempts as a whole — network failures, server
    /// rejections and DeviceCheck faults alike. Also serialises them: without
    /// this, concurrent failing requests each kick off their own reset and race
    /// on Keychain state, generating fresh App Attest keys back-to-back, which
    /// Apple then rejects (DCError 2/3).
    private static let attestGate = RetryGate(
        label: "Attestation",
        baseDelay: 5,
        maxDelay: 5 * 60
    )

    /// The DeviceCheck entry point that faulted.
    ///
    /// A closed set of values, which is the point: the raw value goes straight
    /// into an HTTP header, so it must never carry framework text we don't
    /// control. (Apple's exception reasons contain selector names, arbitrary
    /// punctuation and, in principle, anything at all.)
    enum DeviceCheckOperation: String {
        case supportCheck = "support-check"
        case generateKey = "generate-key"
        case attestKey = "attest-key"
        case generateAssertion = "generate-assertion"
    }

    private static let faultOperationLock = NSLock()
    private static var lastFaultOperation: DeviceCheckOperation?

    /// Non-nil while DeviceCheck is being given a rest after faulting; the
    /// reason it faulted. Clears itself once the backoff window expires.
    static var deviceCheckFault: String? {
        deviceCheckGate.isCoolingDown ? deviceCheckGate.failureReason : nil
    }

    /// Which call faulted, while the backoff window is open. Reported to the
    /// server on fail-open requests so we can still see this happening once the
    /// exception barrier has stopped it showing up as a crash.
    static var deviceCheckFaultOperation: DeviceCheckOperation? {
        guard deviceCheckGate.isCoolingDown else { return nil }
        faultOperationLock.lock()
        defer { faultOperationLock.unlock() }
        return lastFaultOperation
    }

    /// True if `error` came out of the Objective-C barrier, i.e. DeviceCheck
    /// raised an exception rather than returning an error.
    private static func isFrameworkFault(_ error: Error) -> Bool {
        (error as NSError).domain == PSPAppAttestErrorDomain
    }

    /// Record a DeviceCheck framework fault and return the error to throw.
    private static func noteDeviceCheckFault(
        _ error: Error,
        operation: DeviceCheckOperation
    ) -> ProsopoError {
        let nsError = error as NSError
        let reason = (nsError.userInfo[PSPAppAttestExceptionReasonKey] as? String)
            ?? nsError.localizedDescription
        return noteDeviceCheckFault(reason: reason, operation: operation)
    }

    private static func noteDeviceCheckFault(
        reason: String,
        operation: DeviceCheckOperation
    ) -> ProsopoError {
        ProsopoLogger.error(
            "DeviceCheck raised an Objective-C exception during \(operation.rawValue) — "
                + "pausing App Attest, requests will pass through unsigned. \(reason)"
        )
        faultOperationLock.lock()
        lastFaultOperation = operation
        faultOperationLock.unlock()

        deviceCheckGate.recordFailure("\(operation.rawValue): \(reason)")
        return ProsopoError.deviceCheckFault(reason)
    }

    /// Perform the full attestation flow: generate key → attest → register.
    /// Called once at `configure()`. It's a no-op if already attested.
    func attestIfNeeded() async throws {
        try await runGatedAttestation(resetFirst: false)
    }

    /// Retry attestation if one is due.
    ///
    /// Safe to call on every intercepted request: it is single-flight and
    /// backoff-gated, so the overwhelming majority of calls return immediately
    /// having touched neither Apple nor the network. Driving retries from
    /// traffic rather than a timer means we retry exactly when it matters — a
    /// request is going out unprotected right now — and do nothing while the
    /// app is idle.
    func retryAttestationIfDue() async {
        switch state {
        case .attested:
            return  // nothing to do
        case .unsupported:
            return  // genuinely unsupported hardware; retrying can't help
        case .uninitialized, .keyGenerated:
            break
        }

        // Respect the DeviceCheck backoff — otherwise attestation retries would
        // walk straight past it and back into the faulting framework.
        guard !Self.deviceCheckGate.isCoolingDown else { return }

        try? await runGatedAttestation(resetFirst: false)
    }

    /// Apple has told us the current key is unusable (`DCError.invalidKey` /
    /// `.invalidInput`). Wipe local state and attest again from scratch.
    func recoverFromUnusableKey() async {
        try? await runGatedAttestation(resetFirst: true)
    }

    /// The one path through the attestation flow, gated so that only one
    /// attempt runs at a time and repeated failures back off.
    private func runGatedAttestation(resetFirst: Bool) async throws {
        guard Self.attestGate.claim() else {
            ProsopoLogger.debug(
                "Attestation already in flight or backing off "
                    + "(\(Int(Self.attestGate.secondsUntilRetry))s to go) — skipping"
            )
            return
        }

        if resetFirst {
            ProsopoLogger.warning("Key unusable — clearing keychain and re-attesting")
            resetState()
        }

        do {
            try await runAttestation()
            Self.attestGate.recordSuccess()
        } catch {
            setLastError(error.localizedDescription)
            Self.attestGate.recordFailure(error.localizedDescription)
            throw error
        }
    }

    private func runAttestation() async throws {
        setPhase("checking keychain")
        if let existingKeyId = KeychainManager.loadKeyId(), KeychainManager.isAttested() {
            setState(.attested(keyId: existingKeyId))
            setPhase("attested (cached)")
            ProsopoLogger.info("Device already attested with keyId: \(existingKeyId)")
            return
        }

        setPhase("checking device support")
        guard let supportState = AppAttestShim.supportState else {
            // DeviceCheck faulted while answering. That's not a verdict on the
            // device, so don't write it off as unsupported — back off and let
            // the retry ask again.
            setState(.uninitialized)
            setPhase("DeviceCheck faulted")
            throw Self.noteDeviceCheckFault(reason: "support check faulted", operation: .supportCheck)
        }
        guard supportState.boolValue else {
            setState(.unsupported)
            setPhase("unsupported device")
            ProsopoLogger.warning("App Attest not supported on this device")
            throw ProsopoError.appAttestNotSupported
        }

        var keyId: String
        if let existingKeyId = KeychainManager.loadKeyId() {
            keyId = existingKeyId
            setPhase("reusing existing key")
            ProsopoLogger.info("Using existing keyId: \(keyId)")
        } else {
            keyId = try await generateAndStoreKey()
        }

        do {
            try await attestKeyAndRegister(keyId: keyId)
        } catch let dcError as DCError where dcError.code == .invalidKey || dcError.code == .invalidInput {
            // Apple no longer recognises this keyId (e.g. the device-side App Attest
            // store was wiped, or the key was already attested in a prior run that
            // we've forgotten about). Wipe local state, generate a fresh key, and
            // retry once before giving up.
            ProsopoLogger.warning("attestKey returned \(dcError.code.rawValue) — regenerating key and retrying")
            KeychainManager.deleteAll()
            setState(.uninitialized)
            keyId = try await generateAndStoreKey()
            try await attestKeyAndRegister(keyId: keyId)
        }
    }

    private func generateAndStoreKey() async throws -> String {
        setPhase("generating key (Apple)")
        let keyId: String
        do {
            keyId = try await AppAttestBarrier.generateKey()
        } catch where Self.isFrameworkFault(error) {
            // Leave the state `.uninitialized`, not `.unsupported` — the device
            // is fine, the framework isn't, and we want the retry to come back.
            setState(.uninitialized)
            setPhase("DeviceCheck faulted")
            throw Self.noteDeviceCheckFault(error, operation: .generateKey)
        }
        guard KeychainManager.saveKeyId(keyId) else {
            throw ProsopoError.attestationFailed("Failed to save keyId to Keychain")
        }
        setState(.keyGenerated(keyId: keyId))
        ProsopoLogger.info("Generated new App Attest key: \(keyId)")
        return keyId
    }

    private func attestKeyAndRegister(keyId: String) async throws {
        setState(.keyGenerated(keyId: keyId))

        setPhase("fetching challenge (Bumblebee)")
        let challengeHex = try await networkClient.fetchChallenge()
        ProsopoLogger.debug("Received attestation challenge")

        guard let challengeData = Data(hexString: challengeHex) else {
            throw ProsopoError.attestationFailed("Invalid challenge hex")
        }
        let clientDataHash = Data(SHA256.hash(data: challengeData))

        setPhase("attesting key (Apple)")
        let attestationObject: Data
        do {
            attestationObject = try await AppAttestBarrier.attestKey(
                keyId,
                clientDataHash: clientDataHash
            )
        } catch where Self.isFrameworkFault(error) {
            // DeviceCheck itself blew up. Don't wipe the Keychain — the key is
            // probably fine and Apple simply failed to process it — just back
            // off from the framework and let the retry pick it up.
            setState(.uninitialized)
            setPhase("DeviceCheck faulted")
            throw Self.noteDeviceCheckFault(error, operation: .attestKey)
        } catch let dcError as DCError {
            switch dcError.code {
            case .serverUnavailable:
                throw ProsopoError.attestationFailed("Apple attestation server unavailable, retry later")
            case .invalidKey, .invalidInput:
                // Re-throw raw so runAttestation can wipe + regenerate + retry once.
                throw dcError
            default:
                KeychainManager.deleteAll()
                setState(.uninitialized)
                throw ProsopoError.attestationFailed(dcError.localizedDescription)
            }
        } catch {
            KeychainManager.deleteAll()
            setState(.uninitialized)
            throw ProsopoError.attestationFailed(error.localizedDescription)
        }

        ProsopoLogger.info("Apple attestation succeeded, submitting to server")

        // Apple has now attested keyId; it cannot be attested again. If anything
        // fails between here and markAttested(), the key is "burned" — leaving
        // it in the Keychain would cause every subsequent launch to load it and
        // get DCError.invalidKey from attestKey forever.
        setPhase("submitting attestation (Bumblebee)")
        do {
            let response = try await networkClient.submitAttestation(
                keyId: keyId,
                attestationObject: attestationObject,
                challenge: challengeHex
            )
            guard response.success else {
                throw ProsopoError.attestationFailed("Server rejected attestation")
            }
        } catch {
            KeychainManager.deleteAll()
            setState(.uninitialized)
            throw error
        }

        _ = KeychainManager.markAttested()
        setState(.attested(keyId: keyId))
        setPhase("attested")
        setLastError(nil)
        ProsopoLogger.info("Device attestation complete")
    }

    // MARK: - Assertion generation

    #if DEBUG
    private var _debugBurnNextAssertions = 0

    /// Test-only: when > 0, the next N `generateAssertion` calls throw a
    /// bridged `DCError.invalidKey` instead of calling Apple. Used to repro
    /// the assertion-failure recovery race condition observed in client logs.
    /// Thread-safe (guarded by `lock`).
    var debugBurnNextAssertions: Int {
        get { lock.withLock { _debugBurnNextAssertions } }
        set { lock.withLock { _debugBurnNextAssertions = newValue } }
    }

    /// Atomically consume one "burn" if any remain. Returns true if a burn was
    /// consumed, so the check-and-decrement cannot race between two concurrent
    /// assertion tasks.
    private func consumeDebugBurn() -> Bool {
        lock.withLock {
            guard _debugBurnNextAssertions > 0 else { return false }
            _debugBurnNextAssertions -= 1
            return true
        }
    }
    #endif

    /// Generate an assertion for a request.
    ///
    /// - Parameters:
    ///   - challenge: The hex-encoded challenge from the server
    ///   - method: The HTTP method (GET, POST, etc.)
    ///   - path: The request path
    /// - Returns: A tuple of (assertion data, client data) to attach to the request
    func generateAssertion(
        challenge: String,
        method: String,
        path: String
    ) async throws -> (assertion: Data, clientData: Data) {
        guard case .attested(let keyId) = state else {
            throw ProsopoError.assertionFailed("Device not attested")
        }

        if let fault = Self.deviceCheckFault {
            throw ProsopoError.deviceCheckFault(fault)
        }

        #if DEBUG
        if consumeDebugBurn() {
            ProsopoLogger.warning("DEBUG: forcing assertion to fail with invalidKey")
            // NSError with the DCError domain bridges to DCError when cast as
            // `error as? DCError`, so the existing recovery path in
            // ProsopoURLProtocol fires unchanged.
            throw NSError(
                domain: DCErrorDomain,
                code: DCError.Code.invalidKey.rawValue,
                userInfo: nil
            )
        }
        #endif

        // Build the client data JSON
        let clientDataStruct = AssertionClientData(
            method: method,
            path: path,
            challenge: challenge,
            timestamp: ISO8601DateFormatter().string(from: Date())
        )
        let clientData = try JSONEncoder().encode(clientDataStruct)
        let clientDataHash = Data(SHA256.hash(data: clientData))

        // Generate the assertion via the Secure Enclave
        let assertion: Data
        do {
            assertion = try await AppAttestBarrier.generateAssertion(
                keyId,
                clientDataHash: clientDataHash
            )
        } catch where Self.isFrameworkFault(error) {
            throw Self.noteDeviceCheckFault(error, operation: .generateAssertion)
        }

        // A working assertion means DeviceCheck is healthy again — clear any
        // outstanding backoff so the next fault starts from the short delay.
        Self.deviceCheckGate.recordSuccess()

        return (assertion, clientData)
    }

    /// Get the current key ID, if attested.
    var keyId: String? {
        switch state {
        case .attested(let id), .keyGenerated(let id):
            return id
        default:
            return nil
        }
    }

    /// Wipe stored credentials and reset state so the next `attestIfNeeded()`
    /// call regenerates a key and re-attests. Used when Apple reports the
    /// current key as invalid (DCError.invalidKey) during assertion.
    func resetState() {
        KeychainManager.deleteAll()
        setState(.uninitialized)
        ProsopoLogger.info("Attestation state reset")
    }
}

// MARK: - Async wrappers over the Objective-C exception barrier

/// `async` façade over `AppAttestShim`.
///
/// These deliberately do *not* call `DCAppAttestService` directly — the whole
/// point is that the DeviceCheck call happens inside an Objective-C frame that
/// can catch an `NSException`. Ordinary `NSError`s (including `DCError`) are
/// forwarded unchanged, so `catch let dcError as DCError` still works upstream.
private enum AppAttestBarrier {
    static func generateKey() async throws -> String {
        try await withCheckedThrowingContinuation { continuation in
            AppAttestShim.generateKey { keyId, error in
                if let error {
                    continuation.resume(throwing: error)
                } else if let keyId {
                    continuation.resume(returning: keyId)
                } else {
                    continuation.resume(
                        throwing: ProsopoError.attestationFailed("generateKey returned no key")
                    )
                }
            }
        }
    }

    static func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            AppAttestShim.attestKey(keyId, clientDataHash: clientDataHash) { attestation, error in
                if let error {
                    continuation.resume(throwing: error)
                } else if let attestation {
                    continuation.resume(returning: attestation)
                } else {
                    continuation.resume(
                        throwing: ProsopoError.attestationFailed("attestKey returned no attestation")
                    )
                }
            }
        }
    }

    static func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            AppAttestShim.generateAssertion(keyId, clientDataHash: clientDataHash) { assertion, error in
                if let error {
                    continuation.resume(throwing: error)
                } else if let assertion {
                    continuation.resume(returning: assertion)
                } else {
                    continuation.resume(
                        throwing: ProsopoError.assertionFailed("generateAssertion returned no assertion")
                    )
                }
            }
        }
    }
}

// MARK: - Data hex extension

extension Data {
    init?(hexString: String) {
        let hex = hexString.dropFirst(hexString.hasPrefix("0x") ? 2 : 0)
        guard hex.count.isMultiple(of: 2) else { return nil }

        var data = Data(capacity: hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let nextIndex = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<nextIndex], radix: 16) else { return nil }
            data.append(byte)
            index = nextIndex
        }
        self = data
    }

    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
