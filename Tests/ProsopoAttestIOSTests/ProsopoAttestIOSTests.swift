// Copyright 2021-2026 Prosopo (UK) Ltd.
// Licensed under the Apache License, Version 2.0

import DeviceCheck
import ProsopoAttestShim
import XCTest
@testable import ProsopoAttestIOS
#if canImport(WebKit)
import WebKit
#endif

/// Covers the Objective-C exception barrier that stands between the SDK and
/// Apple's DeviceCheck framework.
///
/// DeviceCheck can raise an `NSException` instead of returning an error —
/// observed on iOS 18 as an unrecognized selector inside
/// `DCAppAttestController`. Swift cannot catch that, so without the barrier the
/// exception terminates the host app. These tests drive the same barrier the
/// DeviceCheck wrappers use, since Apple's framework cannot be made to fault on
/// demand.
/// Lock-protected holder, so a completion handler can hand a result back to the
/// test body without mutating a captured `var` across a concurrency boundary.
private final class Box<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: Value

    init(_ value: Value) {
        stored = value
    }

    var value: Value {
        get {
            lock.lock()
            defer { lock.unlock() }
            return stored
        }
        set {
            lock.lock()
            stored = newValue
            lock.unlock()
        }
    }
}

final class AppAttestBarrierTests: XCTestCase {

    private func runBarrier(
        _ body: @escaping (@escaping (Any?, Error?) -> Void) -> Void
    ) -> (value: Any?, error: NSError?) {
        let result = Box<(value: Any?, error: NSError?)>((nil, nil))
        let done = expectation(description: "barrier finished")
        AppAttestShim.performBarriered({ finish in
            body { value, error in finish(value, error) }
        }, completion: { value, error in
            result.value = (value, error as NSError?)
            done.fulfill()
        })
        wait(for: [done], timeout: 5)
        return result.value
    }

    /// The core guarantee: an exception raised inside the barrier comes back as
    /// an error instead of tearing down the process.
    func testRaisedExceptionBecomesAnError() {
        let result = runBarrier { _ in
            NSException(
                name: .invalidArgumentException,
                reason: "-[DCDeviceMetadataDaemonConnection loadKey]: unrecognized selector sent to instance",
                userInfo: nil
            ).raise()
        }

        XCTAssertNil(result.value)
        let error = try? XCTUnwrap(result.error)
        XCTAssertEqual(error?.domain, PSPAppAttestErrorDomain)
        XCTAssertEqual(error?.code, PSPAppAttestErrorCode.frameworkFault.rawValue)
    }

    /// The exception's name and reason must survive into the error, or the
    /// crash is untriageable once it's no longer crashing.
    func testExceptionDetailsArePreserved() {
        let reason = "-[DCDeviceMetadataDaemonConnection loadKey]: unrecognized selector"
        let result = runBarrier { _ in
            NSException(name: .invalidArgumentException, reason: reason, userInfo: nil).raise()
        }

        let error = try? XCTUnwrap(result.error)
        XCTAssertEqual(error?.userInfo[PSPAppAttestExceptionNameKey] as? String,
                       NSExceptionName.invalidArgumentException.rawValue)
        XCTAssertEqual(error?.userInfo[PSPAppAttestExceptionReasonKey] as? String, reason)
        XCTAssertTrue(error?.localizedDescription.contains(reason) ?? false)
    }

    /// A normal completion is passed straight through — the barrier must not
    /// disturb the happy path.
    func testSuccessPassesThrough() {
        let result = runBarrier { finish in finish("key-id", nil) }

        XCTAssertEqual(result.value as? String, "key-id")
        XCTAssertNil(result.error)
    }

    /// DeviceCheck's own `NSError`s (including `DCError`) must reach the Swift
    /// layer untouched, so the existing invalidKey recovery path still fires.
    func testDeviceCheckErrorIsNotRewritten() {
        let dcError = NSError(domain: "com.apple.devicecheck.error", code: 2, userInfo: nil)
        let result = runBarrier { finish in finish(nil, dcError) }

        XCTAssertEqual(result.error?.domain, "com.apple.devicecheck.error")
        XCTAssertEqual(result.error?.code, 2)
    }

    /// If DeviceCheck ever both completes *and* throws, only the first result
    /// may escape. The Swift layer resumes a `CheckedContinuation` here, and
    /// resuming twice traps — which would swap one crash for another.
    func testCompletionRunsAtMostOnce() {
        let calls = Box(0)
        let done = expectation(description: "barrier finished")
        AppAttestShim.performBarriered({ finish in
            finish("first", nil)
            NSException(name: .invalidArgumentException, reason: "late throw", userInfo: nil).raise()
        }, completion: { value, error in
            calls.value += 1
            XCTAssertEqual(value as? String, "first")
            XCTAssertNil(error)
            done.fulfill()
        })

        wait(for: [done], timeout: 5)
        XCTAssertEqual(
            calls.value, 1,
            "the exception after completion must be swallowed, not re-delivered"
        )
    }

    /// The support check is called on the main thread at startup and has itself been
    /// reported to fault inside DeviceCheck; it must never throw out to Swift.
    func testIsSupportedDoesNotThrow() {
        XCTAssertNoThrow(AppAttestShim.supportState)
    }
}

/// Covers the backoff gate that decides when attestation is retried and when
/// DeviceCheck is left alone after faulting.
///
/// The behaviour that matters most here is that nothing is ever disabled
/// permanently — an unattested device is unprotected, so the gate must always
/// come back round to trying again.
final class RetryGateTests: XCTestCase {

    private func makeGate(base: TimeInterval = 0.05, max: TimeInterval = 1) -> RetryGate {
        RetryGate(label: "test", baseDelay: base, maxDelay: max)
    }

    func testFirstAttemptIsAllowedImmediately() {
        let gate = makeGate()
        XCTAssertTrue(gate.claim())
        XCTAssertFalse(gate.isCoolingDown)
        XCTAssertNil(gate.failureReason)
    }

    /// Single-flight: a burst of concurrent requests must produce one
    /// attestation attempt, not one each. Back-to-back key generation is
    /// exactly what Apple rejects.
    func testOnlyOneAttemptRunsAtATime() {
        let gate = makeGate()
        XCTAssertTrue(gate.claim())
        XCTAssertFalse(gate.claim())
        XCTAssertFalse(gate.claim())

        gate.recordSuccess()
        XCTAssertTrue(gate.claim(), "slot should free up once the attempt finishes")
    }

    func testFailureOpensABackoffWindow() {
        let gate = makeGate(base: 60)
        XCTAssertTrue(gate.claim())
        gate.recordFailure("boom")

        XCTAssertTrue(gate.isCoolingDown)
        XCTAssertFalse(gate.claim(), "must not retry inside the backoff window")
        XCTAssertEqual(gate.failureReason, "boom")
        XCTAssertGreaterThan(gate.secondsUntilRetry, 0)
    }

    /// The point of the whole exercise: the gate reopens. Failing once must not
    /// leave the device unattested forever.
    func testBackoffWindowExpiresAndAllowsARetry() {
        let gate = makeGate(base: 0.1)
        XCTAssertTrue(gate.claim())
        gate.recordFailure("transient")
        XCTAssertFalse(gate.claim())

        let reopened = expectation(description: "gate reopened")
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.3) {
            XCTAssertFalse(gate.isCoolingDown)
            XCTAssertTrue(gate.claim(), "gate must reopen once the window passes")
            reopened.fulfill()
        }
        wait(for: [reopened], timeout: 5)
    }

    func testDelayGrowsWithConsecutiveFailures() {
        let gate = makeGate(base: 10, max: 10_000)

        _ = gate.claim()
        gate.recordFailure("1")
        let first = gate.secondsUntilRetry

        gate.recordFailure("2")
        let second = gate.secondsUntilRetry

        gate.recordFailure("3")
        let third = gate.secondsUntilRetry

        XCTAssertGreaterThan(second, first)
        XCTAssertGreaterThan(third, second)
    }

    func testDelayIsCapped() {
        let gate = makeGate(base: 10, max: 30)
        for index in 1...12 {
            gate.recordFailure("failure \(index)")
        }
        XCTAssertLessThanOrEqual(gate.secondsUntilRetry, 30)
    }

    /// One success wipes the streak, so a later blip starts from the short
    /// delay again rather than the capped one.
    func testSuccessResetsTheStreak() {
        let gate = makeGate(base: 10, max: 10_000)
        for _ in 1...5 {
            gate.recordFailure("repeated")
        }
        let escalated = gate.secondsUntilRetry

        gate.recordSuccess()
        XCTAssertFalse(gate.isCoolingDown)
        XCTAssertNil(gate.failureReason)

        gate.recordFailure("fresh")
        XCTAssertLessThan(gate.secondsUntilRetry, escalated)
    }

    /// Bailing out before doing the work must not count as a failure, or a
    /// caller that changed its mind would push out everyone else's retry.
    func testAbandonedClaimDoesNotBackOff() {
        let gate = makeGate()
        XCTAssertTrue(gate.claim())
        gate.abandonClaim()

        XCTAssertFalse(gate.isCoolingDown)
        XCTAssertTrue(gate.claim())
    }


    /// The shape the key-recovery gate uses: never claimed, only failed, and
    /// asked `isCoolingDown` before each attempt.
    ///
    /// It has to work without `claim()` because the thing being throttled is not
    /// an attempt that can fail — the attestation it triggers succeeds every
    /// time. What is being counted is a verdict that arrives later, from Apple,
    /// about a key that was minted earlier. Recording that verdict must arm the
    /// window on its own.
    func testCooldownOnlyUsageEscalatesWithoutClaiming() {
        let gate = RetryGate(label: "recovery", baseDelay: 10, maxDelay: 600)

        XCTAssertFalse(gate.isCoolingDown)

        gate.recordFailure("key unusable")
        XCTAssertTrue(gate.isCoolingDown)
        let first = gate.secondsUntilRetry

        gate.recordFailure("key unusable again")
        XCTAssertGreaterThan(
            gate.secondsUntilRetry,
            first,
            "a second bad key must buy a longer pause than the first"
        )
    }
}

/// The fault marker sent on fail-open requests, which is how a DeviceCheck
/// fault stays visible now that the exception barrier stops it reaching the
/// host app's crash reporter.
final class DeviceCheckFaultReportingTests: XCTestCase {

    private let allOperations: [AppAttestManager.DeviceCheckOperation] = [
        .supportCheck, .generateKey, .attestKey, .generateAssertion,
    ]

    /// These raw values go straight into an HTTP header. Apple's exception
    /// reasons contain selector names and arbitrary punctuation, so the header
    /// must carry only this closed set — never framework text.
    func testOperationValuesAreSafeToPutInAHeader() {
        for operation in allOperations {
            let value = operation.rawValue
            XCTAssertFalse(value.isEmpty)
            XCTAssertTrue(
                value.allSatisfy { character in
                    character.isASCII && (character.isLowercase || character == "-")
                },
                "\(value) must be lowercase ASCII and dashes only"
            )
        }
    }

    func testOperationValuesAreDistinct() {
        let values = Set(allOperations.map(\.rawValue))
        XCTAssertEqual(values.count, allOperations.count)
    }

    /// No fault, no header — ordinary not-yet-attested traffic must not be
    /// tagged, or the signal is worthless.
    func testNoFaultOperationReportedWhenHealthy() {
        XCTAssertNil(AppAttestManager.deviceCheckFaultOperation)
        XCTAssertNil(AppAttestManager.deviceCheckFault)
    }
}

final class ProsopoAttestIOSTests: XCTestCase {
    func testHexStringConversion() {
        let hex = "deadbeef"
        let data = Data(hexString: hex)
        XCTAssertNotNil(data)
        XCTAssertEqual(data?.count, 4)
        XCTAssertEqual(data?.hexString, hex)
    }

    func testInvalidHexString() {
        let data = Data(hexString: "zzzz")
        XCTAssertNil(data)
    }

    func testOddLengthHexString() {
        let data = Data(hexString: "abc")
        XCTAssertNil(data)
    }

    // MARK: - Assertion header contract

    /// The header names are a contract with the Protect server and must match
    /// exactly what the native `ProsopoURLProtocol` sends, since the WebView shim
    /// reuses them. A typo here silently drops protection.
    func testAssertionHeaderNames() {
        XCTAssertEqual(ProsopoAttestIOS.keyIdHeader, "X-Prosopo-KeyId")
        XCTAssertEqual(ProsopoAttestIOS.assertionHeader, "X-Prosopo-Assertion")
        XCTAssertEqual(ProsopoAttestIOS.clientDataHeader, "X-Prosopo-ClientData")
        XCTAssertEqual(ProsopoAttestIOS.challengeHeader, "X-Prosopo-Challenge")
        XCTAssertEqual(ProsopoAttestIOS.nextChallengeHeader, "X-Prosopo-Next-Challenge")
        XCTAssertEqual(ProsopoAttestIOS.statusHeader, "X-Prosopo-Status")
        XCTAssertEqual(ProsopoAttestIOS.noSessionStatus, "no-session")
    }

    // MARK: - Session deferral

    private func response(status: Int, headers: [String: String] = [:]) -> HTTPURLResponse {
        HTTPURLResponse(
            url: URL(string: "https://example.test/api/thing")!,
            statusCode: status,
            httpVersion: "HTTP/1.1",
            headerFields: headers
        )!
    }

    /// The response the edge sends when it default-denies an unsigned
    /// cookie-less JSON request. It is a deferral, not a refusal, and it is the
    /// one thing worth replaying.
    func testSessionDeferralIsRecognised() {
        let deferred = response(
            status: 401,
            headers: [ProsopoAttestIOS.statusHeader: ProsopoAttestIOS.noSessionStatus]
        )
        XCTAssertTrue(ProsopoAttestIOS.isSessionDeferral(deferred))
    }

    /// HTTP header values are not case-normalised for us, and nothing stops the
    /// edge or an intermediary changing the casing.
    func testSessionDeferralIgnoresHeaderValueCasing() {
        let deferred = response(status: 401, headers: [ProsopoAttestIOS.statusHeader: "No-Session"])
        XCTAssertTrue(ProsopoAttestIOS.isSessionDeferral(deferred))
    }

    /// A bare 401 belongs to the customer's own API — their auth expiring, say.
    /// Replaying it would be us silently retrying someone else's failure, so the
    /// marker header is required, not merely checked when present.
    func testAPlain401IsNotADeferral() {
        XCTAssertFalse(ProsopoAttestIOS.isSessionDeferral(response(status: 401)))
    }

    /// A 403 is an access rule saying no. That is terminal by design, and
    /// re-sending it with an assertion attached would not change the answer.
    func testABlockIsNotADeferral() {
        let blocked = response(
            status: 403,
            headers: [ProsopoAttestIOS.statusHeader: ProsopoAttestIOS.noSessionStatus]
        )
        XCTAssertFalse(ProsopoAttestIOS.isSessionDeferral(blocked))
    }

    func testASuccessIsNotADeferral() {
        XCTAssertFalse(ProsopoAttestIOS.isSessionDeferral(response(status: 200)))
        XCTAssertFalse(ProsopoAttestIOS.isSessionDeferral(nil))
    }

    /// A non-HTTP response cannot carry the marker, and must not be coerced into
    /// looking like one.
    func testANonHTTPResponseIsNotADeferral() {
        let raw = URLResponse(
            url: URL(string: "https://example.test/api/thing")!,
            mimeType: nil,
            expectedContentLength: 0,
            textEncodingName: nil
        )
        XCTAssertFalse(ProsopoAttestIOS.isSessionDeferral(raw))
    }

    /// Fail-open: when the shared SDK has not been configured/attested,
    /// `assertionHeaders` returns nil so callers forward the request unmodified
    /// rather than blocking the user. Relies on the singleton being unconfigured
    /// in the test process (no test calls `configure`).
    ///
    /// This also pins the ordering that keeps the readiness gate safe. The gate
    /// is only ever opened by `configure`, so an unconfigured app must be
    /// answered *before* the wait — otherwise every request in an app that never
    /// called `configure` hangs until the watchdog fires. The `await` completing
    /// at all is the assertion; a regression here deadlocks the test.
    func testAssertionHeadersFailOpenWhenUnconfigured() async {
        let headers = await ProsopoAttestIOS.shared.assertionHeaders(method: "GET", path: "/api/foo")
        XCTAssertNil(headers)
        XCTAssertFalse(
            ProsopoAttestIOS.shared.attestationReady.isReady,
            "unconfigured SDK must not have opened the gate"
        )
    }

    // MARK: - Readiness gate

    /// The cold-start latch: closed until something opens it. This is the state
    /// an app's first requests arrive in, and the reason they used to go out
    /// unsigned.
    func testGateStartsClosed() {
        let gate = ReadinessGate()
        XCTAssertFalse(gate.isReady)
    }

    /// Opening releases waiters. Without this the gate would be a deadlock
    /// rather than a delay.
    func testWaitersAreReleasedWhenTheGateOpens() async {
        let gate = ReadinessGate()
        let waiterCount = 8

        async let waiters: Void = withTaskGroup(of: Void.self) { group in
            for _ in 0..<waiterCount {
                group.addTask { await gate.wait() }
            }
            await group.waitForAll()
        }

        // Give the waiters a moment to actually suspend on the gate rather than
        // racing `open()` to it — the interesting path is the queued one.
        try? await Task.sleep(nanoseconds: 50_000_000)
        gate.open()

        await waiters
        XCTAssertTrue(gate.isReady)
    }

    /// Once open, waiting is free. Every request after the first attestation
    /// settles takes this path, so it must not suspend.
    func testWaitReturnsImmediatelyOnceOpen() async {
        let gate = ReadinessGate()
        gate.open()

        let start = Date()
        await gate.wait()
        XCTAssertLessThan(Date().timeIntervalSince(start), 0.5)
    }

    /// Both the attestation task's `defer` and the watchdog call `open()`, and
    /// neither knows about the other. The second call must be a no-op rather
    /// than resuming a continuation twice, which traps.
    func testOpenIsIdempotent() async {
        let gate = ReadinessGate()
        gate.open()
        gate.open()
        gate.open()
        await gate.wait()
        XCTAssertTrue(gate.isReady)
    }

    /// A waiter that arrives after the gate is already open must still be
    /// resumed — the re-check inside the continuation is what guarantees it.
    func testWaiterArrivingAfterOpenIsNotStranded() async {
        let gate = ReadinessGate()
        gate.open()
        await gate.wait()
        await gate.wait()
        XCTAssertTrue(gate.isReady)
    }

    /// The gate's timeout bounds our worst-case contribution to the host app's
    /// launch latency. It is a product decision, not an implementation detail,
    /// so it is pinned.
    func testGateTimeoutIsBounded() {
        XCTAssertEqual(ProsopoAttestIOS.attestationGateTimeout, 4)
    }

    // MARK: - Challenge claiming

    /// THE BUG. A challenge is single-use server-side, so two overlapping
    /// requests must never be handed the same one — whichever assertion arrives
    /// second is refused, and its request then goes out unsigned and is 401'd.
    ///
    /// The old shape read the cached value and cleared it in a *separate* call
    /// after the assertion had been minted, leaving a window in which the actor
    /// would serve it again. Claiming has to take and clear in one hop.
    func testABankedChallengeIsHandedToExactlyOneCaller() async throws {
        let manager = ChallengeManager(networkClient: unreachableClient())
        await manager.store(challenge: "banked-challenge")

        // Only one of these can legitimately return the banked value. The other
        // must go to the network — which is unreachable here, so it throws.
        // That is the assertion: a second caller is never given the same string.
        async let first = try? await manager.takeChallenge(keyId: "k")
        async let second = try? await manager.takeChallenge(keyId: "k")
        let claimed = await [first, second].compactMap { $0 }

        XCTAssertEqual(claimed, ["banked-challenge"])
        let stillBanked = await manager.hasBankedChallenge
        XCTAssertFalse(stillBanked, "claiming must clear the bank")
    }

    /// Claiming twice in sequence must also only yield the challenge once —
    /// the same invariant, without the concurrency, so a failure here points at
    /// the clear rather than at the isolation.
    func testClaimingTwiceDoesNotReuseTheChallenge() async throws {
        let manager = ChallengeManager(networkClient: unreachableClient())
        await manager.store(challenge: "banked-challenge")

        let first = try await manager.takeChallenge(keyId: "k")
        XCTAssertEqual(first, "banked-challenge")

        do {
            _ = try await manager.takeChallenge(keyId: "k")
            XCTFail("second claim must not reuse the banked challenge")
        } catch {
            // Expected: nothing banked, so it tried the unreachable network.
        }
    }

    /// A piggybacked challenge that arrives while an assertion is in flight must
    /// survive. The old `consumeCurrent()` cleared unconditionally *after* the
    /// assertion, so it wiped whatever had been banked in the meantime and
    /// forced the next request to pay for a fetch.
    func testStoringAfterAClaimKeepsTheNewChallenge() async throws {
        let manager = ChallengeManager(networkClient: unreachableClient())
        await manager.store(challenge: "first")

        _ = try await manager.takeChallenge(keyId: "k")
        await manager.store(challenge: "second")

        let next = try await manager.takeChallenge(keyId: "k")
        XCTAssertEqual(next, "second")
    }

    /// A client pointed at an address nothing answers on, so `fetchChallenge`
    /// fails rather than hanging the suite on a real network call.
    private func unreachableClient() -> NetworkClient {
        NetworkClient(
            serverURL: URL(string: "https://127.0.0.1:1")!,
            siteKey: "test-site-key"
        )
    }

#if canImport(WebKit)
    /// Installing protection into a configuration adds the JS shim user script
    /// and is safe to call more than once on the same configuration.
    @MainActor
    func testWebviewInstallAddsShimAndIsRepeatable() {
        let configuration = WKWebViewConfiguration()
        let before = configuration.userContentController.userScripts.count

        ProsopoProtectWebview.install(into: configuration)
        XCTAssertEqual(configuration.userContentController.userScripts.count, before + 1)

        // Re-installing must not throw (handlers are removed before re-adding).
        ProsopoProtectWebview.install(into: configuration)
        XCTAssertEqual(configuration.userContentController.userScripts.count, before + 2)
    }

    /// The bridge message names the shim posts to must match the names the native
    /// handlers are registered under.
    func testWebviewBridgeMessageNames() {
        XCTAssertEqual(ProsopoWebviewBridge.assertionMessage, "prosopoAssertion")
        XCTAssertEqual(ProsopoWebviewBridge.challengeMessage, "prosopoChallenge")
    }
#endif
}

/// The iOS 27 re-attestation loop, emulated.
///
/// Apple's half is what could not be reached before: App Attest does not exist
/// on macOS, so the real enclave can never mint a key, let alone disown one.
/// With the Apple layer behind `AppAttestProviding` it can be stood in for, and
/// the observed behaviour reproduced exactly — attestation always succeeds, and
/// each key stops working after about a dozen assertions.
///
/// Measured on the device that prompted this: 52 keys in 2h18m, against 1 in
/// 6h on iOS 26.
final class AttestationLoopTests: XCTestCase {

    /// Stands in for the Secure Enclave on a device where Apple keeps
    /// invalidating keys. Attestation works every time; the key it produced
    /// dies `assertionsPerKey` assertions later, which is the shape the logs
    /// show and the shape no gate was watching for.
    private final class DyingKeyProvider: AppAttestProviding, @unchecked Sendable {
        private let assertionsPerKey: Int
        private let lock = NSLock()
        private var minted = 0
        private var assertionsOnCurrentKey = 0

        init(assertionsPerKey: Int) {
            self.assertionsPerKey = assertionsPerKey
        }

        /// How many App Attest keys Apple has been asked for. This is the
        /// number the backoff exists to bound.
        var keysMinted: Int { lock.withLock { minted } }

        var supportState: Bool? { true }

        func generateKey() async throws -> String {
            lock.withLock {
                minted += 1
                assertionsOnCurrentKey = 0
                return "key-\(minted)"
            }
        }

        func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data {
            Data("attestation-object".utf8)
        }

        func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data {
            let dead = lock.withLock { () -> Bool in
                assertionsOnCurrentKey += 1
                return assertionsOnCurrentKey > assertionsPerKey
            }
            guard !dead else {
                throw NSError(domain: DCErrorDomain, code: DCError.Code.invalidKey.rawValue)
            }
            return Data("assertion".utf8)
        }
    }

    private struct StubTransport: AttestTransport {
        func fetchChallenge(keyId: String?) async throws -> String { "00ff" }
        func submitAttestation(
            keyId: String,
            attestationObject: Data,
            challenge: String
        ) async throws -> AttestResponse {
            AttestResponse(success: true, keyId: keyId)
        }
    }

    private final class MemoryKeyStore: KeyStore, @unchecked Sendable {
        private let lock = NSLock()
        private var keyId: String?
        private var attested = false

        func loadKeyId() -> String? { lock.withLock { keyId } }
        func isAttested() -> Bool { lock.withLock { attested } }
        func saveKeyId(_ newValue: String) -> Bool { lock.withLock { keyId = newValue; return true } }
        func markAttested() -> Bool { lock.withLock { attested = true; return true } }
        func deleteAll() { lock.withLock { keyId = nil; attested = false } }
    }

    /// One lap of the app's behaviour, as `ProsopoAttestIOS.assertionHeaders`
    /// performs it: if the device is unattested the request goes out bare and
    /// nudges a retry on the way; otherwise it is signed, and Apple calling the
    /// key dead triggers a recovery.
    ///
    /// Both the `isUnusableKey` filter and the retry nudge live on the shared
    /// singleton, and are inlined here so the test drives the manager without
    /// configuring it.
    private func makeRequests(_ count: Int, through manager: AppAttestManager) async {
        for _ in 0..<count {
            guard case .attested = manager.state else {
                await manager.retryAttestationIfDue()
                continue
            }

            do {
                _ = try await manager.generateAssertion(
                    challenge: "00ff", method: "GET", path: "/services/catalogue"
                )
            } catch let error as NSError where error.code == DCError.Code.invalidKey.rawValue {
                await manager.recoverFromUnusableKey()
            } catch {
                XCTFail("unexpected assertion error: \(error)")
            }
        }
    }

    private func makeManager(
        provider: AppAttestProviding
    ) -> AppAttestManager {
        AppAttestManager(
            networkClient: StubTransport(),
            provider: provider,
            keyStore: MemoryKeyStore(),
            attestGate: RetryGate(label: "test-attest", baseDelay: 5, maxDelay: 300),
            keyRecoveryGate: RetryGate(label: "test-recovery", baseDelay: 5, maxDelay: 1800)
        )
    }

    /// THE REPRODUCTION. 120 requests against a device that kills a key every
    /// 12 assertions is ten dead keys' worth of provocation.
    ///
    /// Unthrottled, the SDK answers each death by minting another key
    /// immediately — which is the behaviour measured in the field, and which
    /// Apple rate-limits. Throttled, the first death is serviced at once and
    /// the rest of the burst is refused until the window expires, so the device
    /// asks Apple for a handful of keys rather than one per death.
    func testKeysMintedAreBoundedWhenAppleKeepsKillingTheKey() async throws {
        let provider = DyingKeyProvider(assertionsPerKey: 12)
        let manager = makeManager(provider: provider)

        try await manager.attestIfNeeded()
        XCTAssertEqual(provider.keysMinted, 1, "precondition: one key to start with")

        await makeRequests(120, through: manager)

        XCTAssertLessThanOrEqual(
            provider.keysMinted, 3,
            "the backoff must bound key generation; unthrottled this reaches ~11"
        )
    }

    /// Inside the window the device must stop claiming to be attested.
    ///
    /// Refusing to mint another key is not the same as carrying on. Apple has
    /// said the key is dead, so a manager still reporting `.attested` sends
    /// every subsequent request through a challenge fetch and an enclave call
    /// to build an assertion that cannot work — and, worse,
    /// `retryAttestationIfDue` sees `.attested` and declines to do anything, so
    /// nothing recovers.
    func testTheDeadKeyIsDroppedWhileTheWindowIsOpen() async throws {
        let provider = DyingKeyProvider(assertionsPerKey: 1)
        let manager = makeManager(provider: provider)

        try await manager.attestIfNeeded()
        XCTAssertNotNil(manager.keyId, "precondition: attested with a key")

        // Two deaths: the first is serviced, the second lands inside the window.
        await makeRequests(4, through: manager)

        XCTAssertGreaterThan(manager.keyRecoveryBackoff, 0, "precondition: window is open")
        XCTAssertNil(
            manager.keyId,
            "a manager inside the recovery window must not still be holding a dead key"
        )
    }

    /// The traffic-driven retry must respect the recovery window too.
    ///
    /// It is the busiest way into attestation, so if it ignored the window it
    /// would mint the key the recovery path had just declined to mint, and the
    /// throttle would exist in name only.
    func testTrafficDrivenRetryDoesNotBypassTheRecoveryWindow() async throws {
        let provider = DyingKeyProvider(assertionsPerKey: 1)
        let manager = makeManager(provider: provider)

        try await manager.attestIfNeeded()
        await makeRequests(4, through: manager)
        let minted = provider.keysMinted

        for _ in 0..<20 {
            await manager.retryAttestationIfDue()
        }

        XCTAssertEqual(
            provider.keysMinted, minted,
            "retries inside the window must not mint keys the recovery path refused"
        )
    }

    /// The backoff must not be a kill switch. Once the window expires the
    /// device is allowed to try again, because the only acceptable resting
    /// state is attested.
    func testRecoveryIsAllowedAgainOnceTheWindowExpires() async throws {
        let provider = DyingKeyProvider(assertionsPerKey: 1)
        let manager = AppAttestManager(
            networkClient: StubTransport(),
            provider: provider,
            keyStore: MemoryKeyStore(),
            attestGate: RetryGate(label: "test-attest", baseDelay: 0.05, maxDelay: 1),
            keyRecoveryGate: RetryGate(label: "test-recovery", baseDelay: 0.2, maxDelay: 1)
        )

        try await manager.attestIfNeeded()
        await makeRequests(4, through: manager)
        let beforeWait = provider.keysMinted

        try await Task.sleep(nanoseconds: 500_000_000)
        await makeRequests(4, through: manager)

        XCTAssertGreaterThan(
            provider.keysMinted, beforeWait,
            "after the window expires the device must be allowed to re-attest"
        )
    }
}

/// The route filter and the learning that keeps it current.
///
/// The measured integration gates two routes out of everything the app calls,
/// so 95% of assertions were minted for requests that never reached Protect.
/// These pin both halves: which paths get signed, and how the set corrects
/// itself without an app release.
final class ProtectedRoutesTests: XCTestCase {

    private var suiteName = ""
    private var defaults = UserDefaults.standard

    override func setUp() {
        super.setUp()
        // A suite per test: the real store persists, and a test that leaked into
        // the next one would pass on the previous one's learning.
        suiteName = "io.prosopo.protect.tests.\(name.hashValue)"
        UserDefaults.standard.removePersistentDomain(forName: suiteName)
        defaults = UserDefaults(suiteName: suiteName) ?? .standard
    }

    override func tearDown() {
        UserDefaults.standard.removePersistentDomain(forName: suiteName)
        super.tearDown()
    }

    private func store(seed: [String] = []) -> ProtectedRoutes {
        ProtectedRoutes(seed: seed, defaults: defaults)
    }

    // MARK: - What gets remembered

    /// The two real protected routes. One is two segments with no identifier,
    /// the other is four with a numeric id on the end — which is why the prefix
    /// is found by stripping identifiers rather than truncating to a depth.
    func testTheRealProtectedRoutesReduceToTheRightPrefixes() {
        XCTAssertEqual(
            ProtectedRoutes.learnablePrefix(from: "/services/g2/inventory/listings/1865040444476362752"),
            "/services/g2/inventory/listings"
        )
        XCTAssertEqual(
            ProtectedRoutes.learnablePrefix(from: "/services/catalogue"),
            "/services/catalogue"
        )
    }

    /// Remembering the identifier would remember one event rather than the
    /// route, and the set would grow without bound while matching almost
    /// nothing.
    func testIdentifierSegmentsAreStripped() {
        XCTAssertEqual(ProtectedRoutes.learnablePrefix(from: "/a/b/123456"), "/a/b")
        XCTAssertEqual(
            ProtectedRoutes.learnablePrefix(from: "/a/b/9F1B4C2E-7A55-4D2E-9C1E-2B7A55D24C11"),
            "/a/b"
        )
        XCTAssertEqual(ProtectedRoutes.learnablePrefix(from: "/a/b/1/2/3"), "/a/b")
    }

    /// A path that is nothing but an identifier leaves no route to remember,
    /// and must not collapse to "/" — which would match everything.
    func testAPathWithNothingButAnIdentifierIsNotLearnable() {
        XCTAssertEqual(ProtectedRoutes.learnablePrefix(from: "/123456"), "")
        XCTAssertEqual(ProtectedRoutes.learnablePrefix(from: "/"), "")

        let routes = store()
        XCTAssertFalse(routes.learn(path: "/123456"))
        XCTAssertTrue(routes.known.isEmpty)
    }

    // MARK: - What gets signed

    /// Knowing nothing, sign everything. The cost of a wasted assertion is a
    /// round trip; the cost of the opposite is every route deferring at once.
    func testAnEmptySetSignsEverything() {
        let routes = store()
        XCTAssertTrue(routes.shouldSign(path: "/services/catalogue"))
        XCTAssertTrue(routes.shouldSign(path: "/anything/at/all"))
    }

    func testOnlyKnownPrefixesAreSignedOnceTheSetIsPopulated() {
        let routes = store(seed: ["/services/catalogue", "/services/g2/inventory/listings"])

        XCTAssertTrue(routes.shouldSign(path: "/services/catalogue"))
        XCTAssertTrue(routes.shouldSign(path: "/services/g2/inventory/listings/186504044"))

        // The five the event screen fires alongside the protected one. These are
        // the 95%.
        XCTAssertFalse(routes.shouldSign(path: "/services/events/186504044"))
        XCTAssertFalse(routes.shouldSign(path: "/services/events/186504044/metrics"))
        XCTAssertFalse(routes.shouldSign(path: "/services/events/186504044/tours"))
        XCTAssertFalse(routes.shouldSign(path: "/services/g2/accounts/event-engagements/186504044"))
    }

    func testSeedsAreNormalisedToLeadingSlash() {
        let routes = store(seed: ["services/catalogue"])
        XCTAssertEqual(routes.known, ["/services/catalogue"])
    }

    // MARK: - Learning

    /// A deferred request is proof the route is protected. This is what keeps
    /// the filter current when the customer attaches Protect to a new route,
    /// with no app release.
    func testADeferredRequestTeachesTheRoute() {
        let routes = store(seed: ["/services/catalogue"])
        XCTAssertFalse(routes.shouldSign(path: "/services/g2/inventory/listings/186504044"))

        XCTAssertTrue(routes.learn(path: "/services/g2/inventory/listings/186504044"))

        XCTAssertTrue(routes.shouldSign(path: "/services/g2/inventory/listings/186504044"))
        XCTAssertTrue(
            routes.shouldSign(path: "/services/g2/inventory/listings/999"),
            "learning one id must cover the route, not just that one event"
        )
    }

    /// Only the first deferral on a route is news; the caller logs on the
    /// change, not on every request.
    func testLearningTheSameRouteTwiceIsNotNews() {
        let routes = store()
        XCTAssertTrue(routes.learn(path: "/services/catalogue"))
        XCTAssertFalse(routes.learn(path: "/services/catalogue"))
    }

    /// What was learned has to outlive the process, or every cold start pays
    /// the deferral again on every route.
    func testLearnedRoutesSurviveARestart() {
        store().learn(path: "/services/g2/inventory/listings/186504044")

        let reopened = store()
        XCTAssertEqual(reopened.known, ["/services/g2/inventory/listings"])
        XCTAssertTrue(reopened.shouldSign(path: "/services/g2/inventory/listings/1"))
    }

    // MARK: - The server's view

    func testTheServerListIsMergedIn() {
        let routes = store()
        XCTAssertTrue(routes.merge(["/services/catalogue", "/services/g2/inventory/listings"]))
        XCTAssertEqual(routes.known, ["/services/catalogue", "/services/g2/inventory/listings"])
    }

    /// Additive, not authoritative. The server omitting a route we learned the
    /// hard way is not evidence it is unprotected — it may simply not have been
    /// requested since the server last looked.
    func testTheServerListDoesNotEraseWhatWasLearned() {
        let routes = store()
        routes.learn(path: "/services/g2/inventory/listings/1")
        routes.merge(["/services/catalogue"])

        XCTAssertEqual(routes.known, ["/services/catalogue", "/services/g2/inventory/listings"])
    }

    func testAnEmptyOrUnchangedServerListIsNotAnUpdate() {
        let routes = store(seed: ["/services/catalogue"])
        XCTAssertFalse(routes.merge([]))
        XCTAssertFalse(routes.merge(["/services/catalogue"]))
    }
}


/// Does the SDK call Apple's `generateAssertion` concurrently on one key?
///
/// This asks a question about our own code, not about Apple's. It needs no
/// device and assumes nothing about what DeviceCheck does under contention —
/// it simply counts how many calls are in flight at once when a screen fans
/// out, which is a fact we can establish here and could otherwise only infer
/// from a customer's logs.
final class AssertionConcurrencyTests: XCTestCase {

    /// Records the high-water mark of overlapping `generateAssertion` calls.
    private final class OverlapCountingProvider: AppAttestProviding, @unchecked Sendable {
        private let lock = NSLock()
        private var inFlight = 0
        private var peak = 0

        /// The most assertions Apple was asked for at the same instant.
        var peakConcurrentAssertions: Int { lock.withLock { peak } }

        var supportState: Bool? { true }
        func generateKey() async throws -> String { "key-1" }
        func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data {
            Data("attestation".utf8)
        }

        func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data {
            lock.withLock {
                inFlight += 1
                peak = max(peak, inFlight)
            }
            // Long enough that genuinely parallel callers overlap here, short
            // enough not to slow the suite.
            try? await Task.sleep(nanoseconds: 20_000_000)
            lock.withLock { inFlight -= 1 }
            return Data("assertion".utf8)
        }
    }

    private struct StubTransport: AttestTransport {
        func fetchChallenge(keyId: String?) async throws -> String { "00ff" }
        func submitAttestation(
            keyId: String, attestationObject: Data, challenge: String
        ) async throws -> AttestResponse {
            AttestResponse(success: true, keyId: keyId)
        }
    }

    private final class MemoryKeyStore: KeyStore, @unchecked Sendable {
        private let lock = NSLock()
        private var keyId: String?
        private var attested = false
        func loadKeyId() -> String? { lock.withLock { keyId } }
        func isAttested() -> Bool { lock.withLock { attested } }
        func saveKeyId(_ v: String) -> Bool { lock.withLock { keyId = v; return true } }
        func markAttested() -> Bool { lock.withLock { attested = true; return true } }
        func deleteAll() { lock.withLock { keyId = nil; attested = false } }
    }

    /// The event screen fires six requests at once. This measures what that
    /// does to Apple.
    func testAScreenFanOutOverlapsAssertionsOnOneKey() async throws {
        let provider = OverlapCountingProvider()
        let manager = AppAttestManager(
            networkClient: StubTransport(),
            provider: provider,
            keyStore: MemoryKeyStore(),
            attestGate: RetryGate(label: "t-attest", baseDelay: 5, maxDelay: 300),
            keyRecoveryGate: RetryGate(label: "t-recovery", baseDelay: 5, maxDelay: 300)
        )
        try await manager.attestIfNeeded()

        await withTaskGroup(of: Void.self) { group in
            for i in 0..<6 {
                group.addTask {
                    _ = try? await manager.generateAssertion(
                        challenge: "00ff", method: "GET", path: "/services/thing/\(i)"
                    )
                }
            }
            await group.waitForAll()
        }

        XCTAssertEqual(
            provider.peakConcurrentAssertions, 1,
            "assertions on one key must not overlap: the enclave hands out its "
                + "counter in call order, and iOS 27 answers overlapping calls with invalidKey"
        )
    }

    /// Serialising must not deadlock or drop callers — every request still gets
    /// its assertion, they just take turns.
    func testEveryConcurrentCallerStillGetsAnAssertion() async throws {
        let provider = OverlapCountingProvider()
        let manager = AppAttestManager(
            networkClient: StubTransport(),
            provider: provider,
            keyStore: MemoryKeyStore(),
            attestGate: RetryGate(label: "t-attest", baseDelay: 5, maxDelay: 300),
            keyRecoveryGate: RetryGate(label: "t-recovery", baseDelay: 5, maxDelay: 300)
        )
        try await manager.attestIfNeeded()

        let results = await withTaskGroup(of: Bool.self) { group -> [Bool] in
            for i in 0..<6 {
                group.addTask {
                    let out = try? await manager.generateAssertion(
                        challenge: "00ff", method: "GET", path: "/services/thing/\(i)"
                    )
                    return out != nil
                }
            }
            var acc: [Bool] = []
            for await r in group { acc.append(r) }
            return acc
        }

        XCTAssertEqual(results.count, 6)
        XCTAssertTrue(results.allSatisfy { $0 }, "no caller may be starved or dropped")
    }
}
