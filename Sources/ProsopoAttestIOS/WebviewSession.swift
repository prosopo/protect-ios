// Copyright 2021-2026 Prosopo (UK) Ltd.
// Licensed under the Apache License, Version 2.0

import Foundation

/// The `prosopo_session` cookies protect.js has set inside the app's WebViews,
/// held so native requests can carry the same session.
///
/// # Why
///
/// On iOS the session is born in the WebView, not in the SDK: protect.js runs
/// in the page and sets `prosopo_session` in WebKit's cookie store. Native
/// requests never see it. `WKWebView` keeps its cookies in its own
/// `WKHTTPCookieStore`, apart from `HTTPCookieStorage.shared`, and the
/// interceptor forwards through an ephemeral session whose jar is empty anyway.
/// So one phone showed up as two identities, a WebView session and an attested
/// device with no session, and Protect had no way to join them. Measured on the
/// live integration: no attested iOS request carried a cookie at all.
///
/// Android avoids this because the SDK owns the session and pushes it into the
/// WebView. Here the direction is the other way round, WebView to native.
///
/// # What it holds
///
/// The cookies as WebKit reported them, per cookie store. They are read off the
/// main thread by the interceptor, so everything is behind a lock. The value is
/// a bearer credential (`{jti}|{jwt}`) and is never logged.
///
/// # How it stays current
///
/// Two ways, because neither is enough alone. The store's change notifications
/// cover the common case. WebKit does not deliver them reliably, though: in
/// testing they only arrived once something read the store. So signed native
/// requests also trigger a re-read, throttled by ``claimRefresh(now:)``. The
/// re-read is never awaited. `WKHTTPCookieStore` is main-thread only, and a
/// request that waited on the main thread would deadlock an app that blocks
/// its main thread on a network call. The cost is that the first signed
/// request after the WebView creates its session can go out without it.
final class WebviewSessionJar: @unchecked Sendable {
    static let cookieName = "prosopo_session"

    /// Minimum gap between request-driven re-reads of the WebView's stores.
    static let refreshInterval: TimeInterval = 5

    private let lock = NSLock()
    private var cookiesByStore: [ObjectIdentifier: [HTTPCookie]] = [:]
    private var lastRefresh: Date?

    /// Whether a request-driven re-read is due, and if so, claim it. At most
    /// one caller in each ``refreshInterval`` gets true.
    func claimRefresh(now: Date = Date()) -> Bool {
        lock.withLock {
            if let last = lastRefresh, now.timeIntervalSince(last) < Self.refreshInterval {
                return false
            }
            lastRefresh = now
            return true
        }
    }

    /// Replace what `store` is known to hold. Called with every cookie in the
    /// store; anything that is not the session cookie is dropped here.
    func replace(_ cookies: [HTTPCookie], from store: ObjectIdentifier) {
        let sessions = cookies.filter { $0.name == Self.cookieName }
        lock.withLock { cookiesByStore[store] = sessions }
    }

    /// The session cookie a browser would send to `url`, if any.
    ///
    /// With more than one candidate the most specific path wins, as it would in
    /// a browser's `Cookie` header ordering.
    func cookie(for url: URL, now: Date = Date()) -> HTTPCookie? {
        let candidates = lock.withLock { cookiesByStore.values.flatMap { $0 } }
        return candidates
            .filter { Self.matches($0, url: url, now: now) }
            .max { $0.path.count < $1.path.count }
    }

    /// `existing` (a `Cookie` header value, or nil) with `cookie` set in it.
    /// An earlier pair with the same name is replaced; every other pair the app
    /// set is kept, in order. Same rule as the Android SDK's `mergeCookie`.
    static func merge(_ cookie: HTTPCookie, into existing: String?) -> String {
        let kept = (existing ?? "")
            .split(separator: ";")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { pair in
                !pair.isEmpty
                    && pair.split(separator: "=", maxSplits: 1).first?
                        .trimmingCharacters(in: .whitespaces) != cookie.name
            }
        return (kept + ["\(cookie.name)=\(cookie.value)"]).joined(separator: "; ")
    }

    /// RFC 6265 domain, path, secure and expiry matching, which is the subset
    /// a session cookie set by protect.js can exercise.
    static func matches(_ cookie: HTTPCookie, url: URL, now: Date) -> Bool {
        guard let host = url.host?.lowercased() else { return false }
        if let expires = cookie.expiresDate, expires <= now { return false }
        if cookie.isSecure, url.scheme?.lowercased() != "https" { return false }

        let domain = cookie.domain.lowercased()
        let domainMatches = domain.hasPrefix(".")
            ? host == String(domain.dropFirst()) || host.hasSuffix(domain)
            : host == domain
        guard domainMatches else { return false }

        let path = url.path.isEmpty ? "/" : url.path
        let cookiePath = cookie.path.isEmpty ? "/" : cookie.path
        guard path.hasPrefix(cookiePath) else { return false }
        return cookiePath.hasSuffix("/")
            || path.count == cookiePath.count
            || path.dropFirst(cookiePath.count).first == "/"
    }
}
