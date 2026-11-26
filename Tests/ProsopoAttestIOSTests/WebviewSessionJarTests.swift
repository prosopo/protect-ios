// Copyright 2021-2026 Prosopo (UK) Ltd.
// Licensed under the Apache License, Version 2.0

import XCTest
@testable import ProsopoAttestIOS
#if canImport(WebKit)
import WebKit
#endif
#if canImport(UIKit)
import UIKit
#endif

/// The WebView's `prosopo_session` riding on native requests.
///
/// Measured on the live integration before this existed: of 1,415 attested iOS
/// requests, none carried a cookie, so the WebView session and the attested
/// device could never be joined. These cover which cookie is picked for a
/// request and how it is merged into the app's own `Cookie` header.
final class WebviewSessionJarTests: XCTestCase {

    private let store = ObjectIdentifier(NSObject())

    private func cookie(
        name: String = WebviewSessionJar.cookieName,
        value: String = "bumblebee-abc|header.payload.signature",
        domain: String = "www.example.com",
        path: String = "/",
        secure: Bool = false,
        expires: Date? = nil
    ) -> HTTPCookie {
        var properties: [HTTPCookiePropertyKey: Any] = [
            .name: name,
            .value: value,
            .domain: domain,
            .path: path,
        ]
        if secure { properties[.secure] = "TRUE" }
        if let expires = expires { properties[.expires] = expires }
        guard let cookie = HTTPCookie(properties: properties) else {
            preconditionFailure("invalid cookie properties: \(properties)")
        }
        return cookie
    }

    private func jar(_ cookies: [HTTPCookie]) -> WebviewSessionJar {
        let jar = WebviewSessionJar()
        jar.replace(cookies, from: store)
        return jar
    }

    private func url(_ string: String) -> URL {
        guard let url = URL(string: string) else { preconditionFailure("bad URL \(string)") }
        return url
    }

    // MARK: - Which cookie

    func testTheSessionCookieIsFoundForItsHost() {
        let session = cookie()
        let found = jar([session]).cookie(for: url("https://www.example.com/services/catalogue"))
        XCTAssertEqual(found?.value, session.value)
    }

    func testOtherCookiesInTheStoreAreIgnored() {
        let jar = jar([cookie(name: "app_pref", value: "dark")])
        XCTAssertNil(jar.cookie(for: url("https://www.example.com/")))
    }

    func testAHostOnlyCookieIsNotSentToAnotherHost() {
        let jar = jar([cookie(domain: "www.example.com")])
        XCTAssertNil(jar.cookie(for: url("https://api.example.com/")))
        XCTAssertNil(jar.cookie(for: url("https://evil-www.example.com/")))
    }

    func testADomainCookieCoversTheApexAndSubdomains() {
        let jar = jar([cookie(domain: ".example.com")])
        XCTAssertNotNil(jar.cookie(for: url("https://example.com/")))
        XCTAssertNotNil(jar.cookie(for: url("https://api.example.com/")))
        XCTAssertNil(jar.cookie(for: url("https://notexample.com/")))
    }

    func testASecureCookieIsNotSentOverPlainHTTP() {
        let jar = jar([cookie(secure: true)])
        XCTAssertNil(jar.cookie(for: url("http://www.example.com/")))
        XCTAssertNotNil(jar.cookie(for: url("https://www.example.com/")))
    }

    func testAnExpiredCookieIsNotSent() {
        let now = Date()
        let jar = jar([cookie(expires: now.addingTimeInterval(-1))])
        XCTAssertNil(jar.cookie(for: url("https://www.example.com/"), now: now))
    }

    func testPathScopingMatchesWholeSegmentsOnly() {
        let jar = jar([cookie(path: "/app")])
        XCTAssertNotNil(jar.cookie(for: url("https://www.example.com/app")))
        XCTAssertNotNil(jar.cookie(for: url("https://www.example.com/app/events")))
        XCTAssertNil(jar.cookie(for: url("https://www.example.com/application")))
    }

    func testTheMostSpecificPathWins() {
        let jar = jar([cookie(value: "root", path: "/"), cookie(value: "app", path: "/app")])
        XCTAssertEqual(jar.cookie(for: url("https://www.example.com/app/events"))?.value, "app")
    }

    func testAStoreThatDropsTheCookieStopsItBeingSent() {
        let jar = jar([cookie()])
        jar.replace([], from: store)
        XCTAssertNil(jar.cookie(for: url("https://www.example.com/")))
    }

    func testEachStoreIsReplacedIndependently() {
        let other = ObjectIdentifier(NSObject())
        let jar = jar([cookie(domain: "www.example.com")])
        jar.replace([cookie(domain: "shop.example.com")], from: other)
        jar.replace([], from: other)
        XCTAssertNotNil(jar.cookie(for: url("https://www.example.com/")))
        XCTAssertNil(jar.cookie(for: url("https://shop.example.com/")))
    }

    // MARK: - Request-driven re-reads

    func testTheFirstRefreshIsClaimedAndTheNextIsThrottled() {
        let jar = WebviewSessionJar()
        let now = Date()
        XCTAssertTrue(jar.claimRefresh(now: now))
        XCTAssertFalse(jar.claimRefresh(now: now.addingTimeInterval(1)))
    }

    func testARefreshIsDueAgainAfterTheInterval() {
        let jar = WebviewSessionJar()
        let now = Date()
        XCTAssertTrue(jar.claimRefresh(now: now))
        XCTAssertTrue(jar.claimRefresh(now: now.addingTimeInterval(WebviewSessionJar.refreshInterval)))
    }

    // MARK: - Merging into the request's Cookie header

    func testMergingIntoNoHeaderGivesJustTheSession() {
        XCTAssertEqual(
            WebviewSessionJar.merge(cookie(value: "j|t"), into: nil),
            "prosopo_session=j|t"
        )
    }

    func testMergingKeepsTheAppsOwnCookies() {
        XCTAssertEqual(
            WebviewSessionJar.merge(cookie(value: "j|t"), into: "a=1; b=2"),
            "a=1; b=2; prosopo_session=j|t"
        )
    }

    func testMergingReplacesAStaleSession() {
        XCTAssertEqual(
            WebviewSessionJar.merge(cookie(value: "new|t"), into: "a=1; prosopo_session=old|t; b=2"),
            "a=1; b=2; prosopo_session=new|t"
        )
    }

    func testMergingSkipsEmptyAndValuelessPairs() {
        XCTAssertEqual(
            WebviewSessionJar.merge(cookie(value: "j|t"), into: "a=1;; flag ;"),
            "a=1; flag; prosopo_session=j|t"
        )
    }

#if canImport(WebKit)
    /// End to end through WebKit: a page setting `prosopo_session` the way
    /// protect.js does makes it available to native requests, with no app code.
    ///
    /// The loop re-reads the store the way a signed request does, rather than
    /// waiting on WebKit's change notification, which is the unreliable half.
    @MainActor
    func testACookieSetByThePageReachesTheJar() async throws {
        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = .nonPersistent()
        ProsopoProtectWebview.install(into: configuration)
        let webView = WKWebView(frame: CGRect(x: 0, y: 0, width: 100, height: 100), configuration: configuration)
#if canImport(UIKit)
        // iOS does not run scripts in a WKWebView that is in no window.
        let window = UIWindow(frame: webView.frame)
        window.addSubview(webView)
        window.makeKeyAndVisible()
        defer { window.isHidden = true }
#endif

        webView.loadHTMLString(
            "<script>document.cookie = 'prosopo_session=bumblebee-webview|jwt; path=/'</script>",
            baseURL: url("https://webview.example.com/")
        )

        let target = url("https://webview.example.com/services/catalogue")
        let deadline = Date().addingTimeInterval(10)
        while ProsopoAttestIOS.shared.webviewSession.cookie(for: target) == nil, Date() < deadline {
            WebviewSessionObserver.shared.refreshAll()
            try await Task.sleep(nanoseconds: 100_000_000)
        }
        XCTAssertEqual(
            ProsopoAttestIOS.shared.webviewSession.cookie(for: target)?.value,
            "bumblebee-webview|jwt"
        )
        XCTAssertNil(
            ProsopoAttestIOS.shared.webviewSession.cookie(for: url("https://other.example.com/")),
            "the session must not leak to a host the page did not set it for"
        )
    }
#endif
}
