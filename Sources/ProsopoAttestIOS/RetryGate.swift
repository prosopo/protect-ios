// Copyright 2021-2026 Prosopo (UK) Ltd.
// Licensed under the Apache License, Version 2.0

import Foundation

/// Exponential-backoff gate, safe to hit from every request task at once.
///
/// Two different callers use it two different ways:
///
/// - **Attestation** calls `claim()` to take a slot. That is single-flight: only
///   one attestation attempt may run at a time, so a burst of concurrent
///   requests can't race each other into generating back-to-back App Attest
///   keys, which Apple rejects.
/// - **Assertion generation** only asks `isCoolingDown`, because many concurrent
///   assertions are perfectly normal. The gate is just answering "is DeviceCheck
///   currently considered unhealthy?".
///
/// Failures back off exponentially from `baseDelay` up to `maxDelay`; a single
/// success clears the streak. Nothing is ever disabled permanently — the caller
/// is expected to keep probing, because being unattested is not an acceptable
/// resting state.
///
/// `@unchecked Sendable` because being shared across concurrent tasks is the
/// entire point of the type — every request task consults the same gate. Every
/// stored property below is either immutable or accessed only under `lock`,
/// which is the invariant the annotation is asserting; new mutable state must
/// keep to it.
final class RetryGate: @unchecked Sendable {
    private let lock = NSLock()
    private let label: String
    private let baseDelay: TimeInterval
    private let maxDelay: TimeInterval

    private var consecutiveFailures = 0
    private var retryAfter: Date = .distantPast
    private var inFlight = false
    private var lastFailureReason: String?

    init(label: String, baseDelay: TimeInterval, maxDelay: TimeInterval) {
        self.label = label
        self.baseDelay = baseDelay
        self.maxDelay = maxDelay
    }

    /// True while inside the backoff window following a failure.
    var isCoolingDown: Bool {
        lock.lock()
        defer { lock.unlock() }
        return Date() < retryAfter
    }

    /// The most recent failure reason, or nil if the last attempt succeeded.
    var failureReason: String? {
        lock.lock()
        defer { lock.unlock() }
        return lastFailureReason
    }

    /// Seconds until the next attempt is allowed; 0 if one is allowed now.
    var secondsUntilRetry: TimeInterval {
        lock.lock()
        defer { lock.unlock() }
        return max(0, retryAfter.timeIntervalSinceNow)
    }

    /// Take the right to make an attempt.
    ///
    /// Returns false if another attempt is already in flight, or if we're still
    /// inside the backoff window. Every successful claim must be followed by
    /// `recordSuccess()`, `recordFailure(_:)`, or `abandonClaim()`.
    func claim() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard !inFlight, Date() >= retryAfter else { return false }
        inFlight = true
        return true
    }

    func recordSuccess() {
        lock.lock()
        let hadFailed = consecutiveFailures > 0
        inFlight = false
        consecutiveFailures = 0
        retryAfter = .distantPast
        lastFailureReason = nil
        lock.unlock()

        if hadFailed {
            ProsopoLogger.info("\(label): recovered")
        }
    }

    func recordFailure(_ reason: String) {
        lock.lock()
        inFlight = false
        consecutiveFailures += 1
        let attempt = consecutiveFailures
        let delay = min(maxDelay, baseDelay * pow(2, Double(attempt - 1)))
        retryAfter = Date().addingTimeInterval(delay)
        lastFailureReason = reason
        lock.unlock()

        ProsopoLogger.warning(
            "\(label): failed \(attempt)x in a row, next attempt in \(Int(delay))s — \(reason)"
        )
    }

    /// Release a claim without recording an outcome — the caller decided not to
    /// go ahead, so this shouldn't count against the backoff.
    func abandonClaim() {
        lock.lock()
        inFlight = false
        lock.unlock()
    }
}
