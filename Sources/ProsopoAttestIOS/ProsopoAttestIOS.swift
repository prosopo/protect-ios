// Copyright 2021-2026 Prosopo (UK) Ltd.
// Licensed under the Apache License, Version 2.0

import DeviceCheck
import Foundation

/// ProsopoAttestIOS SDK — transparent App Attest integration for iOS apps.
///
/// ## Usage
///
/// Call `configure` once during app launch:
///
/// ```swift
/// ProsopoAttestIOS.configure(siteKey: "your-site-key", serverURL: "https://protect.prosopo.io")
/// ```
///
/// After configuration, all requests made through `URLSession.shared` are
/// automatically protected with App Attest assertions. No other changes
/// are needed in your networking code.
public final class ProsopoAttestIOS: @unchecked Sendable {

    /// Shared singleton instance.
    public static let shared = ProsopoAttestIOS()

    /// Version of this SDK build. Bumped per shipped zip; surfaced in the
    /// configure log line so a customer's logs identify which build is running.
    public static let sdkVersion = "0.1.5"

    // MARK: - Internal state

    private(set) var siteKey: String?
    private(set) var serverURL: URL?
    private(set) var isConfigured = false

    private(set) var networkClient: NetworkClient?
    private(set) var attestManager: AppAttestManager?
    private(set) var challengeManager: ChallengeManager?

    /// The domains to intercept. If empty, all domains are intercepted.
    /// Set via `configure(siteKey:serverURL:protectedDomains:)`.
    private(set) var protectedDomains: [String] = []

    /// Holds intercepted requests until the first attestation attempt settles,
    /// so an app that fetches on launch doesn't race its own attestation and
    /// send the opening requests unsigned. See ``ReadinessGate``.
    let attestationReady = ReadinessGate()

    /// Hard cap on how long ``attestationReady`` may hold a request, measured
    /// from `configure()`.
    ///
    /// Its unit is not "attestation timeout" but "how long we are willing to
    /// make the customer's users wait for us", so it is set to what a working
    /// attestation comfortably fits inside rather than to what a struggling one
    /// might eventually need. A warm launch resolves from the Keychain in
    /// milliseconds; a cold one costs a DeviceCheck round trip plus a call to
    /// `/api/ios/attest`. Matches `SESSION_GATE_TIMEOUT_MS` in the web bundle,
    /// which bounds the same risk on the same reasoning.
    static let attestationGateTimeout: TimeInterval = 4

    private init() {}

    // MARK: - Public API

    /// Configure the SDK and start the attestation flow.
    ///
    /// Call this once, as early as possible (e.g., in `AppDelegate` or `@main App.init`).
    ///
    /// - Parameters:
    ///   - siteKey: Your Prosopo site key
    ///   - serverURL: The Bumblebee server URL (e.g., "https://protect.prosopo.io")
    ///   - protectedDomains: Optional list of domains to protect. If empty, all requests are intercepted.
    public static func configure(
        siteKey: String,
        serverURL: String,
        protectedDomains: [String] = []
    ) {
        guard let url = URL(string: serverURL) else {
            ProsopoLogger.error("Invalid server URL: \(serverURL)")
            return
        }

        KeychainManager.wipeIfFreshInstall()

        let instance = shared
        instance.siteKey = siteKey
        instance.serverURL = url
        instance.protectedDomains = protectedDomains
        instance.isConfigured = true

        let client = NetworkClient(serverURL: url, siteKey: siteKey)
        instance.networkClient = client
        instance.attestManager = AppAttestManager(networkClient: client)
        instance.challengeManager = ChallengeManager(networkClient: client)

        // Register the URL protocol for transparent request interception
        URLProtocol.registerClass(ProsopoURLProtocol.self)

        ProsopoLogger.info("ProsopoAttestIOS \(Self.sdkVersion) configured with siteKey: \(siteKey)")

        // Start attestation in background. Requests are held behind
        // `attestationReady` until this settles, so "non-blocking" now means
        // "does not block `configure`" rather than "the first requests go out
        // unsigned".
        Task {
            defer { instance.attestationReady.open() }
            do {
                try await instance.attestManager?.attestIfNeeded()
            } catch {
                ProsopoLogger.error("Background attestation failed: \(error.localizedDescription)")
            }
        }

        // Backstop for the paths that fail by hanging rather than by throwing,
        // which the `defer` above cannot reach.
        Task {
            try? await Task.sleep(
                nanoseconds: UInt64(Self.attestationGateTimeout * 1_000_000_000)
            )
            if !instance.attestationReady.isReady {
                ProsopoLogger.error(
                    "Attestation did not settle within \(Int(Self.attestationGateTimeout))s — "
                        + "releasing held requests so the app behaves normally"
                )
                instance.attestationReady.open()
            }
        }
    }

    // MARK: - State queries

    /// Whether the device has been successfully attested.
    public var isAttested: Bool {
        if case .attested = attestManager?.state {
            return true
        }
        return false
    }

    /// Whether App Attest is supported on this device.
    public var isSupported: Bool {
        attestManager?.isSupported ?? false
    }

    /// The current attestation state, for debugging.
    public var attestationState: String {
        guard let manager = attestManager else { return "not configured" }
        switch manager.state {
        case .uninitialized: return "uninitialized"
        case .keyGenerated: return "key generated (not yet attested)"
        case .attested: return "attested"
        case .unsupported: return "unsupported device"
        }
    }

    /// Granular phase of the in-progress attestation flow ("fetching challenge",
    /// "attesting key (Apple)", etc.). Useful for on-screen debugging.
    public var attestationPhase: String {
        attestManager?.phase ?? "not configured"
    }

    /// Last error message seen during attestation or assertion, if any.
    public var lastError: String? {
        attestManager?.lastError
    }

    /// Non-nil while App Attest is paused because Apple's DeviceCheck framework
    /// raised an Objective-C exception. Requests pass through unsigned during
    /// the pause — they still succeed, they're just unprotected — and the SDK
    /// probes DeviceCheck again when the backoff window expires. The value is
    /// the exception reason, for bug reports.
    public var deviceCheckFault: String? {
        AppAttestManager.deviceCheckFault
    }

    /// First few characters of the current keyId, for on-screen debugging.
    public var keyIdPreview: String {
        guard let keyId = attestManager?.keyId else { return "<none>" }
        return String(keyId.prefix(12)) + "…"
    }

    #if DEBUG
    /// Test-only: force the next N intercepted requests to fail their
    /// `generateAssertion` call with a synthesised `DCError.invalidKey`.
    /// Used together with concurrent requests to reproduce the assertion-
    /// failure recovery race condition without waiting for it to occur in
    /// the wild. No-op in Release builds.
    public func _debugBurnNextAssertions(count: Int) {
        attestManager?.debugBurnNextAssertions = count
        ProsopoLogger.warning("DEBUG: next \(count) assertions will fail with invalidKey")
    }
    #endif

    /// Force a full re-attestation: wipes the keychain and triggers the flow again.
    /// Call this from a debug UI button when a device gets stuck in a bad state.
    public func forceReset() {
        attestManager?.resetState()
        Task {
            do {
                try await attestManager?.attestIfNeeded()
            } catch {
                ProsopoLogger.error("Forced re-attestation failed: \(error.localizedDescription)")
            }
        }
    }

    // MARK: - Assertion headers (shared by URLProtocol + WebView bridge)

    /// The App Attest assertion header names attached to a protected request.
    /// Exposed so the WebView JS shim and the native protocol stay in lockstep.
    static let keyIdHeader = "X-Prosopo-KeyId"
    static let assertionHeader = "X-Prosopo-Assertion"
    static let clientDataHeader = "X-Prosopo-ClientData"
    static let challengeHeader = "X-Prosopo-Challenge"

    /// Header on a server response carrying the next piggybacked challenge.
    static let nextChallengeHeader = "X-Prosopo-Next-Challenge"

    /// Mint a fresh set of App Attest assertion headers for a single request.
    ///
    /// This is the one place assertions are generated. Both the native
    /// `ProsopoURLProtocol` and the `ProsopoProtectWebview` bridge call it so the
    /// two transports protect requests identically and recover from a burned key
    /// in exactly the same way.
    ///
    /// Fail-open: returns `nil` when the device is not configured/attested or when
    /// assertion generation fails (after kicking off recovery), so callers forward
    /// the request unmodified rather than blocking the user.
    ///
    /// - Parameters:
    ///   - method: HTTP method of the request being signed (e.g. `"GET"`).
    ///   - path: URL path of the request being signed (e.g. `"/api/foo"`).
    /// - Returns: Header name→value pairs to attach, or `nil` to forward unmodified.
    func assertionHeaders(method: String, path: String) async -> [String: String]? {
        // Unconfigured is answered without waiting: the gate is only ever opened
        // by `configure`, so waiting on it here would hang every request in an
        // app that never called it.
        guard isConfigured else {
            ProsopoLogger.debug("Not configured, request will be forwarded unmodified")
            return nil
        }

        // The cold-start latch. Free once open, which is every call after the
        // first attestation attempt settles.
        await attestationReady.wait()

        guard isAttested,
              let attestManager = attestManager,
              let challengeManager = challengeManager,
              let keyId = attestManager.keyId
        else {
            ProsopoLogger.debug("Not attested yet, request will be forwarded unmodified")
            // Nudge attestation along on the way out. Going unattested is a hole
            // in the protection, so a request arriving while we're in that state
            // is exactly the moment to try again. The call is single-flight and
            // backoff-gated, so it's nearly free on the hot path. Detached from
            // this call so the request forwards without waiting on it.
            if let attestManager = attestManager {
                Task { await attestManager.retryAttestationIfDue() }
            }
            return nil
        }

        // Two attempts, because the cheap failure here is a bad challenge and
        // the cost of being wrong is a request the edge refuses.
        //
        // An attested device that cannot mint an assertion used to fail open
        // immediately: the request went out bare, and a bare request has
        // neither an assertion nor a session cookie, so Protect's cookie-less
        // JSON path default-denies it with a 401 the app cannot recover from.
        // Giving up after one try therefore bought nothing — it converted a
        // recoverable stumble into a user-visible failure. So try again with a
        // freshly fetched challenge first, and only then fall open.
        //
        // The retry bypasses the banked challenge deliberately. A banked
        // challenge that just failed is the likeliest cause: spent by an
        // overlapping request, or expired while the app was backgrounded.
        // Re-reading it would fail identically.
        var lastError: Error?
        for attempt in 0..<2 {
            do {
                let challenge = attempt == 0
                    ? try await challengeManager.takeChallenge(keyId: keyId)
                    : try await challengeManager.fetchFreshChallenge(keyId: keyId)
                let (assertion, clientData) = try await attestManager.generateAssertion(
                    challenge: challenge,
                    method: method,
                    path: path
                )
                if attempt > 0 {
                    ProsopoLogger.info("Assertion succeeded on retry with a fresh challenge")
                }
                return [
                    Self.keyIdHeader: keyId,
                    Self.assertionHeader: assertion.base64EncodedString(),
                    Self.clientDataHeader: clientData.base64EncodedString(),
                    Self.challengeHeader: challenge,
                ]
            } catch {
                lastError = error
                // Apple saying the key is unusable is not a challenge problem,
                // and `handleAssertionFailure` has already started a re-attest.
                // Retrying against the same dead key would burn a challenge and
                // fail the same way, so stop here.
                if isUnusableKey(error) {
                    break
                }
                ProsopoLogger.warning(
                    "Assertion attempt \(attempt + 1) failed: \(error.localizedDescription)"
                )
            }
        }

        if let lastError = lastError {
            ProsopoLogger.error(
                "Assertion generation failed: \(lastError.localizedDescription)"
            )
            handleAssertionFailure(lastError)
        }
        return nil
    }

    /// Has Apple told us this key is dead? Retrying cannot help if so.
    private func isUnusableKey(_ error: Error) -> Bool {
        guard let dcError = error as? DCError else { return false }
        return dcError.code == .invalidKey || dcError.code == .invalidInput
    }

    /// Store a challenge piggybacked on a response (from either transport).
    func storeNextChallenge(_ challenge: String) {
        guard let challengeManager = challengeManager else { return }
        Task { await challengeManager.store(challenge: challenge) }
    }

    /// Recovery for a failed assertion: if Apple reports the key as unusable,
    /// wipe local state and re-attest.
    ///
    /// The single-flight guarantee lives on the manager's attestation gate, so a
    /// burst of concurrent failing requests — native or WebView — produces one
    /// reset, not one per request, and repeated failures back off rather than
    /// hammering Apple with fresh keys (which it rejects with DCError 2/3).
    private func handleAssertionFailure(_ error: Error) {
        guard isUnusableKey(error), let attestManager = attestManager else { return }

        ProsopoLogger.warning("Apple reports the key as unusable: \(error.localizedDescription)")
        Task { await attestManager.recoverFromUnusableKey() }
    }

    // MARK: - Internal helpers

    /// Check if a request should be intercepted by the URL protocol.
    func shouldIntercept(_ request: URLRequest) -> Bool {
        guard isConfigured else { return false }
        guard let host = request.url?.host else { return false }

        // Never intercept requests to the Bumblebee server itself (by host AND port)
        if let serverHost = serverURL?.host,
           let serverPort = serverURL?.port,
           host == serverHost,
           request.url?.port == serverPort {
            return false
        }

        // If no protected domains specified, intercept everything
        if protectedDomains.isEmpty {
            return true
        }

        return protectedDomains.contains(host)
    }
}
