// Copyright 2021-2026 Prosopo (UK) Ltd.
// Licensed under the Apache License, Version 2.0

import Foundation

/// Lets exactly one caller run at a time, including across `await`.
///
/// # Why not an actor
///
/// An `actor` does not do this. An actor method that suspends can be re-entered
/// by another task while it is suspended, so two callers can both be inside it
/// with one of them parked on an `await` — which is precisely the overlap this
/// type exists to prevent.
///
/// # Why not a lock
///
/// `NSLock` cannot be held across an `await`; doing so blocks a cooperative
/// thread and is a hard error under the Swift 6 language mode. The lock here
/// guards only the queue, and is never held while the body runs.
///
/// Handover on `release` is deliberate: the slot is passed straight to the next
/// waiter rather than being freed and re-contested, so callers run in the order
/// they arrived and none can be starved.
final class AsyncSerialiser: @unchecked Sendable {
    private let lock = NSLock()
    private var busy = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    /// Run `body`, waiting if another caller is already running.
    func run<T>(_ body: () async throws -> T) async rethrows -> T {
        await acquire()
        defer { release() }
        return try await body()
    }

    private func acquire() async {
        lock.lock()
        if !busy {
            busy = true
            lock.unlock()
            return
        }
        lock.unlock()

        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            lock.lock()
            // Re-checked under the lock: the holder may have released between
            // the fast path above and here, and a waiter queued after that
            // point would never be resumed.
            if !busy {
                busy = true
                lock.unlock()
                continuation.resume()
                return
            }
            waiters.append(continuation)
            lock.unlock()
        }
    }

    private func release() {
        lock.lock()
        if waiters.isEmpty {
            busy = false
            lock.unlock()
            return
        }
        let next = waiters.removeFirst()
        // `busy` stays true — the slot is handed over, not released.
        lock.unlock()
        next.resume()
    }
}
