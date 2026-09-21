// Copyright 2021-2026 Prosopo (UK) Ltd.
// Licensed under the Apache License, Version 2.0

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

    /// The header names are a contract with the Bumblebee server and must match
    /// exactly what the native `ProsopoURLProtocol` sends, since the WebView shim
    /// reuses them. A typo here silently drops protection.
    func testAssertionHeaderNames() {
        XCTAssertEqual(ProsopoAttestIOS.keyIdHeader, "X-Prosopo-KeyId")
        XCTAssertEqual(ProsopoAttestIOS.assertionHeader, "X-Prosopo-Assertion")
        XCTAssertEqual(ProsopoAttestIOS.clientDataHeader, "X-Prosopo-ClientData")
        XCTAssertEqual(ProsopoAttestIOS.challengeHeader, "X-Prosopo-Challenge")
        XCTAssertEqual(ProsopoAttestIOS.nextChallengeHeader, "X-Prosopo-Next-Challenge")
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
