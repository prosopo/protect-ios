// Copyright 2021-2026 Prosopo (UK) Ltd.
// Licensed under the Apache License, Version 2.0

import Foundation

/// One-way latch that holds intercepted requests until attestation has had its
/// first chance to run.
///
/// # Why this exists
///
/// `configure()` arms the URL protocol and kicks attestation off in a detached
/// task. Those two things do not happen in a defined order relative to the host
/// app's own first requests: the interceptor is live the instant it is
/// registered, while the attestation task has not necessarily been scheduled
/// yet. An app that fetches on launch therefore sends its opening requests
/// through an SDK that is configured but holds no key, and `assertionHeaders`
/// fails open — the request goes out bare.
///
/// That is invisible in the SDK and fatal at the edge. A bare request carries
/// neither an assertion nor a `prosopo_session` cookie, so Protect's cookie-less
/// JSON path default-denies it with a 401. The web bundle never hits this
/// because it has the same latch (`sessionReadyPromise` in
/// `packages/protect/src/index.ts`); the native SDK did not.
///
/// It is not rare. On a live integration the losing requests carried no
/// `x-prosopo-keyid` at all and no DeviceCheck fault, which is the signature of
/// a key that did not exist yet rather than one that failed to mint, and every
/// one of them was answered with a 401 the app cannot recover from.
///
/// # Why it is one-way
///
/// The latch covers the cold-start window and nothing else. It is never
/// re-closed — not by `forceReset()`, not by a mid-session re-attest — because
/// a gate that can close again is a gate that can wedge the host app's
/// networking, which is a far worse failure than a request going unsigned.
/// Re-attestation mid-session is already covered by `retryAttestationIfDue`,
/// driven off the traffic itself.
///
/// For the same reason the latch opens on a watchdog as well as on completion:
/// attestation that fails by hanging — a black-holed host, DeviceCheck not
/// returning — must not hold traffic for longer than
/// `ProsopoAttestIOS.attestationGateTimeout`.
final class ReadinessGate: @unchecked Sendable {
    private let lock = NSLock()
    private var isOpen = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    /// Whether the gate has been opened. Thread-safe.
    var isReady: Bool {
        lock.withLock { isOpen }
    }

    /// Open the gate and release everything waiting on it.
    ///
    /// Idempotent: the second and later calls are no-ops, so it is safe to call
    /// from both the attestation task's completion and the watchdog without
    /// either needing to know about the other.
    func open() {
        lock.lock()
        guard !isOpen else {
            lock.unlock()
            return
        }
        isOpen = true
        let pending = waiters
        waiters.removeAll()
        lock.unlock()

        // Resumed outside the lock: a continuation may run its task inline, and
        // that task can call straight back into `isReady`.
        for continuation in pending {
            continuation.resume()
        }
    }

    /// Suspend until the gate opens. Returns immediately once it has.
    func wait() async {
        lock.lock()
        if isOpen {
            lock.unlock()
            return
        }
        lock.unlock()

        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            lock.lock()
            // Re-checked under the lock: `open()` may have run between the fast
            // path above and here, and a continuation added after that point
            // would never be resumed.
            if isOpen {
                lock.unlock()
                continuation.resume()
                return
            }
            waiters.append(continuation)
            lock.unlock()
        }
    }
}
