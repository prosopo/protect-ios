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
    private let networkClient: AttestTransport
    private let provider: AppAttestProviding
    private let keyStore: KeyStore

    /// The backoff gates. Injected so a test can drive the attestation
    /// lifecycle against gates it owns; in the app they are the process-wide
    /// pair, because the conditions they track — Apple rate-limiting us, a
    /// faulting framework — are properties of the device, not of an instance.
    private let attestGate: RetryGate
    private let keyRecoveryGate: RetryGate

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

    init(
        networkClient: AttestTransport,
        provider: AppAttestProviding = DeviceCheckProvider(),
        keyStore: KeyStore = KeychainStore(),
        attestGate: RetryGate = AppAttestManager.sharedAttestGate,
        keyRecoveryGate: RetryGate = AppAttestManager.sharedKeyRecoveryGate
    ) {
        self.networkClient = networkClient
        self.provider = provider
        self.keyStore = keyStore
        self.attestGate = attestGate
        self.keyRecoveryGate = keyRecoveryGate
    }

    /// Check if App Attest is supported on this device. Reports `false` if the
    /// support check itself faulted — see `runAttestation` for the case where
    /// that distinction matters.
    var isSupported: Bool {
        provider.supportState ?? false
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
    static let sharedAttestGate = RetryGate(
        label: "Attestation",
        baseDelay: 5,
        maxDelay: 5 * 60
    )

    /// Backoff for "Apple says the key we are holding is dead".
    ///
    /// `attestGate` cannot damp this. The loop is attest → assert →
    /// `invalidKey` → wipe → attest, and *every attestation in it succeeds*, so
    /// `attestGate` clears its streak on each lap and throttles nothing. An
    /// iOS 27 device was measured minting 52 App Attest keys in two hours this
    /// way. Apple rate-limits key generation, so past some point that churn is
    /// manufacturing the very errors it is reacting to.
    ///
    /// Never cleared within a process run, deliberately. A successful
    /// attestation is not evidence that the key is good — a key that dies a
    /// dozen assertions later attests perfectly well every time — and clearing
    /// on a successful assertion would reset the streak on each lap, which is
    /// the bug restated. A device that genuinely recovers pays five seconds
    /// once and never notices.
    ///
    /// The cap is a straight trade and there is no setting that avoids it. While
    /// the window is open the device is unattested, so every protected route
    /// answers 401 and the replay cannot rescue it — there is no key to sign
    /// with. Shorten the cap and the app works more of the time but burns more
    /// keys; lengthen it and the reverse. The measured device managed ~26 keys
    /// an hour unthrottled, so anything under about two and a half minutes
    /// makes the churn *worse*, which rules out the seconds-scale cap that the
    /// user-facing argument seems to call for.
    ///
    /// Five minutes: ~12 keys an hour, less than half the observed rate, and a
    /// worst-case outage a user might sit through once. The way out of the
    /// trade is a session cookie on the allowed iOS path, so a device that has
    /// proved itself once can ride out the window without a key at all.
    static let sharedKeyRecoveryGate = RetryGate(
        label: "Key recovery",
        baseDelay: 5,
        maxDelay: 5 * 60
    )

    /// The attestation currently running, so a caller that loses the claim can
    /// wait for its result instead of walking away.
    ///
    /// Without this, "someone else is attesting" and "attestation has finished"
    /// are indistinguishable to a caller, and the only safe thing it can do is
    /// give up — so a request goes out unsigned while the attestation that
    /// would have signed it is milliseconds from finishing.
    private static let inFlightLock = NSLock()
    private static var inFlightAttestation: Task<Error?, Never>?

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

    /// Seconds until another key recovery is allowed, 0 if one is allowed now.
    /// Surfaced so a device stuck in a re-attest loop says so on screen, not
    /// only in a log nobody is reading.
    var keyRecoveryBackoff: TimeInterval {
        keyRecoveryGate.secondsUntilRetry
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

        // And the recovery backoff. Traffic-driven retries are the busiest way
        // into attestation, so without this they would mint the key the
        // recovery path just declined to mint, and the throttle would exist in
        // name only.
        guard !keyRecoveryGate.isCoolingDown else { return }

        try? await runGatedAttestation(resetFirst: false)
    }

    /// Apple has told us the current key is unusable (`DCError.invalidKey` /
    /// `.invalidInput`). Wipe local state and attest again from scratch.
    func recoverFromUnusableKey() async {
        guard !keyRecoveryGate.isCoolingDown else {
            // Refusing to mint is not the same as carrying on as before. Apple
            // has told us this key is dead, so the state and the Keychain entry
            // that say otherwise are now a lie, and leaving them in place makes
            // every subsequent request pay a challenge fetch and an enclave call
            // to produce an assertion that cannot work. Drop them and wait: the
            // device is unattested until the window expires, and it should say
            // so.
            ProsopoLogger.warning(
                "Key reported unusable again inside the recovery backoff "
                    + "(\(Int(keyRecoveryGate.secondsUntilRetry))s to go) — dropping the dead key "
                    + "and waiting rather than minting another"
            )
            resetState()
            return
        }
        // Armed before the attempt, not after, so a burst of concurrent
        // assertion failures produces one recovery rather than one each.
        keyRecoveryGate.recordFailure("Apple reported the App Attest key unusable")
        try? await runGatedAttestation(resetFirst: true)
    }

    /// What taking the attestation slot got us.
    private enum AttestationSlot {
        case started(Task<Error?, Never>)
        case joining(Task<Error?, Never>)
        case backingOff
    }

    /// Take the slot: start an attempt, join the one already running, or report
    /// that we are inside the backoff window.
    ///
    /// Synchronous by construction, so the lock is never held across an `await`.
    /// Claiming and publishing happen under the one lock, so a caller arriving
    /// between the two cannot mistake a just-started attempt for no attempt and
    /// walk away. Creating the `Task` inside the lock is safe: its body takes
    /// the gate and manager locks but never this one, so there is no cycle.
    private func takeAttestationSlot(resetFirst: Bool) -> AttestationSlot {
        Self.inFlightLock.withLock {
            guard attestGate.claim() else {
                if let running = Self.inFlightAttestation {
                    return .joining(running)
                }
                return .backingOff
            }

            let attempt = Task<Error?, Never> { [self] in
                if resetFirst {
                    ProsopoLogger.warning("Key unusable — clearing keychain and re-attesting")
                    resetState()
                }

                do {
                    try await runAttestation()
                    attestGate.recordSuccess()
                    return nil
                } catch {
                    setLastError(error.localizedDescription)
                    attestGate.recordFailure(error.localizedDescription)
                    return error
                }
            }
            Self.inFlightAttestation = attempt
            return .started(attempt)
        }
    }

    private static func retire(_ attempt: Task<Error?, Never>) {
        inFlightLock.withLock {
            if inFlightAttestation == attempt {
                inFlightAttestation = nil
            }
        }
    }

    /// The one path through the attestation flow, gated so that only one
    /// attempt runs at a time and repeated failures back off.
    private func runGatedAttestation(resetFirst: Bool) async throws {
        let attempt: Task<Error?, Never>

        switch takeAttestationSlot(resetFirst: resetFirst) {
        case .backingOff:
            ProsopoLogger.debug(
                "Attestation backing off (\(Int(attestGate.secondsUntilRetry))s to go) — skipping"
            )
            return
        case .joining(let running):
            ProsopoLogger.debug("Attestation already in flight — waiting for it to settle")
            _ = await running.value
            return
        case .started(let started):
            attempt = started
        }

        let failure = await attempt.value
        Self.retire(attempt)

        if let failure {
            throw failure
        }
    }

    private func runAttestation() async throws {
        setPhase("checking keychain")
        if let existingKeyId = keyStore.loadKeyId(), keyStore.isAttested() {
            setState(.attested(keyId: existingKeyId))
            setPhase("attested (cached)")
            ProsopoLogger.info("Device already attested with keyId: \(existingKeyId)")
            return
        }

        setPhase("checking device support")
        guard let supportState = provider.supportState else {
            // DeviceCheck faulted while answering. That's not a verdict on the
            // device, so don't write it off as unsupported — back off and let
            // the retry ask again.
            setState(.uninitialized)
            setPhase("DeviceCheck faulted")
            throw Self.noteDeviceCheckFault(reason: "support check faulted", operation: .supportCheck)
        }
        guard supportState else {
            setState(.unsupported)
            setPhase("unsupported device")
            ProsopoLogger.warning("App Attest not supported on this device")
            throw ProsopoError.appAttestNotSupported
        }

        var keyId: String
        if let existingKeyId = keyStore.loadKeyId() {
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
            keyStore.deleteAll()
            setState(.uninitialized)
            keyId = try await generateAndStoreKey()
            try await attestKeyAndRegister(keyId: keyId)
        }
    }

    private func generateAndStoreKey() async throws -> String {
        setPhase("generating key (Apple)")
        let keyId: String
        do {
            keyId = try await provider.generateKey()
        } catch where Self.isFrameworkFault(error) {
            // Leave the state `.uninitialized`, not `.unsupported` — the device
            // is fine, the framework isn't, and we want the retry to come back.
            setState(.uninitialized)
            setPhase("DeviceCheck faulted")
            throw Self.noteDeviceCheckFault(error, operation: .generateKey)
        }
        guard keyStore.saveKeyId(keyId) else {
            throw ProsopoError.attestationFailed("Failed to save keyId to Keychain")
        }
        setState(.keyGenerated(keyId: keyId))
        ProsopoLogger.info("Generated new App Attest key: \(keyId)")
        return keyId
    }

    private func attestKeyAndRegister(keyId: String) async throws {
        setState(.keyGenerated(keyId: keyId))

        setPhase("fetching challenge (Protect)")
        // No keyId: the key exists locally but the server has never seen it,
        // which is the whole point of the call that follows.
        let challengeHex = try await networkClient.fetchChallenge(keyId: nil)
        ProsopoLogger.debug("Received attestation challenge")

        guard let challengeData = Data(hexString: challengeHex) else {
            throw ProsopoError.attestationFailed("Invalid challenge hex")
        }
        let clientDataHash = Data(SHA256.hash(data: challengeData))

        setPhase("attesting key (Apple)")
        let attestationObject: Data
        do {
            attestationObject = try await provider.attestKey(keyId, clientDataHash: clientDataHash)
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
                keyStore.deleteAll()
                setState(.uninitialized)
                throw ProsopoError.attestationFailed(dcError.localizedDescription)
            }
        } catch {
            keyStore.deleteAll()
            setState(.uninitialized)
            throw ProsopoError.attestationFailed(error.localizedDescription)
        }

        ProsopoLogger.info("Apple attestation succeeded, submitting to server")

        // Apple has now attested keyId; it cannot be attested again. If anything
        // fails between here and markAttested(), the key is "burned" — leaving
        // it in the Keychain would cause every subsequent launch to load it and
        // get DCError.invalidKey from attestKey forever.
        setPhase("submitting attestation (Protect)")
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
            keyStore.deleteAll()
            setState(.uninitialized)
            throw error
        }

        _ = keyStore.markAttested()
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
            assertion = try await provider.generateAssertion(keyId, clientDataHash: clientDataHash)
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
        keyStore.deleteAll()
        setState(.uninitialized)
        ProsopoLogger.info("Attestation state reset")
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
