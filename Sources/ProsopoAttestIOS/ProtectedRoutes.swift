// Copyright 2021-2026 Prosopo (UK) Ltd.
// Licensed under the Apache License, Version 2.0

import Foundation

/// The set of path prefixes known to be gated by Protect, so the SDK can stop
/// signing the ones that are not.
///
/// # Why
///
/// Protect is attached to specific routes, not to whole origins. On the
/// integration that prompted this it is two: `/services/catalogue` and
/// `/services/g2/inventory/listings`. The SDK signed every path on every
/// configured host, so measured over twelve hours it minted 430,497 assertions
/// against 19,869 the edge actually verified — 95% of them for requests that
/// never reach Protect at all. Each one costs a round trip to fetch a challenge
/// before the user's request can leave the device.
///
/// # Where the list comes from
///
/// Three sources, in increasing order of authority, all merged:
///
/// 1. whatever the host app passed to `configure`, as a warm start;
/// 2. what the server reports on the challenge response, which is derived from
///    the paths Protect actually sees, so it is the routing rather than a guess
///    at it;
/// 3. what a 401 taught us — a request we declined to sign and the edge
///    deferred was, by definition, on a protected route.
///
/// (3) is what keeps this from being tied to app releases. The customer attaches
/// Protect to a new route in their CDN, the first request to it is deferred, the
/// replay signs it, the prefix is remembered, and every request after that is
/// signed — with no new build and nothing to configure.
///
/// # Why being wrong is cheap
///
/// A missing prefix costs one deferred request and a replay, not a failure, and
/// it is self-correcting. It cannot open a hole: the edge is the enforcement
/// point, and an unsigned request to a protected route is refused whether or not
/// the SDK decided to sign it. Declining to sign withholds proof; it does not
/// grant access.
final class ProtectedRoutes: @unchecked Sendable {
    private static let storageKey = "io.prosopo.protect.protectedRoutes"

    private let lock = NSLock()
    private let defaults: UserDefaults
    private var prefixes: Set<String>

    /// - Parameters:
    ///   - seed: prefixes supplied by the host app. Merged with, never replacing,
    ///     what has already been learned.
    ///   - defaults: injected for tests.
    init(seed: [String], defaults: UserDefaults = .standard) {
        self.defaults = defaults
        let stored = defaults.stringArray(forKey: Self.storageKey) ?? []
        prefixes = Set(stored).union(seed.map(Self.normalise))
        persistLocked()
    }

    /// Every prefix currently known. Sorted so logs and tests are stable.
    var known: [String] {
        lock.withLock { prefixes.sorted() }
    }

    /// Should a request to `path` carry an assertion?
    ///
    /// Empty means we know nothing yet, and the safe answer while we know
    /// nothing is to sign — the cost is a wasted assertion, where the cost of
    /// the opposite is a deferred request on every route at once.
    func shouldSign(path: String) -> Bool {
        lock.withLock {
            guard !prefixes.isEmpty else { return true }
            return prefixes.contains { path.hasPrefix($0) }
        }
    }

    /// Record that `path` turned out to be protected. Returns true if this was
    /// news, so the caller can log a change rather than every deferral.
    @discardableResult
    func learn(path: String) -> Bool {
        let prefix = Self.learnablePrefix(from: path)
        guard !prefix.isEmpty else { return false }

        return lock.withLock {
            guard prefixes.insert(prefix).inserted else { return false }
            persistLocked()
            return true
        }
    }

    /// Merge the server's view. Additive: the server knowing about a route we
    /// have not seen is useful, and the server *not* mentioning one we learned
    /// the hard way is not evidence it is unprotected — it may simply not have
    /// been requested since the server last looked.
    @discardableResult
    func merge(_ serverPrefixes: [String]) -> Bool {
        let incoming = Set(serverPrefixes.map(Self.normalise)).subtracting([""])
        guard !incoming.isEmpty else { return false }

        return lock.withLock {
            let before = prefixes.count
            prefixes.formUnion(incoming)
            guard prefixes.count != before else { return false }
            persistLocked()
            return true
        }
    }

    /// Must be called with `lock` held.
    private func persistLocked() {
        defaults.set(Array(prefixes), forKey: Self.storageKey)
    }

    // MARK: - Path handling

    private static func normalise(_ prefix: String) -> String {
        let trimmed = prefix.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return "" }
        return trimmed.hasPrefix("/") ? trimmed : "/" + trimmed
    }

    /// Reduce a concrete path to the prefix worth remembering.
    ///
    /// Trailing identifier-ish segments are dropped, because remembering
    /// `/services/g2/inventory/listings/1865040444476362752` would remember one
    /// event rather than the route, and the set would grow without bound while
    /// matching almost nothing. `/services/catalogue` keeps every segment, since
    /// none of them look like an identifier — which is why this strips rather
    /// than truncating to a fixed depth: the two protected routes on the
    /// integration that prompted this are two segments and four.
    static func learnablePrefix(from path: String) -> String {
        var segments = path.split(separator: "/", omittingEmptySubsequences: true).map(String.init)
        while let last = segments.last, isIdentifier(last) {
            segments.removeLast()
        }
        guard !segments.isEmpty else { return "" }
        return "/" + segments.joined(separator: "/")
    }

    /// A segment that names an instance rather than a route: all digits, or a
    /// UUID, or a long opaque token.
    private static func isIdentifier(_ segment: String) -> Bool {
        if segment.allSatisfy(\.isNumber) { return true }
        if UUID(uuidString: segment) != nil { return true }
        return segment.count >= 24 && segment.allSatisfy { $0.isHexDigit || $0 == "-" || $0 == "_" }
    }
}
