// Copyright 2021-2026 Prosopo (UK) Ltd.
// Licensed under the Apache License, Version 2.0

#if canImport(WebKit)
import Foundation
import WebKit

/// A `WKWebView` that transparently protects its network traffic with App Attest
/// assertions — the iOS counterpart to the Android `ProsopoProtectWebview`.
///
/// ## What "the same as Android" means here
///
/// On Android the wrapper shares a static `prosopo_session` cookie between the
/// WebView and native HTTP clients. iOS has no such cookie: native requests are
/// protected by per-request App Attest assertion headers injected via
/// `ProsopoURLProtocol`. `WKWebView`, however, does **not** use `URLSession`, so
/// that protocol never sees WebView traffic. The equivalent behaviour is achieved
/// by injecting a JavaScript shim (a `WKUserScript`) that patches `fetch` and
/// `XMLHttpRequest`, and a native bridge that mints the *same* assertion headers
/// (through the *same* `AppAttestManager`/`ChallengeManager` the native path uses)
/// on demand. The result: WebView requests and native requests carry identical
/// `X-Prosopo-*` headers and share one attestation identity.
///
/// ## Usage
///
/// Configure the SDK once, then create a protected WebView:
///
/// ```swift
/// ProsopoAttestIOS.configure(siteKey: "…", serverURL: "https://protect.prosopo.io")
/// let protected = ProsopoProtectWebview()
/// view.addSubview(protected.webView)
/// protected.load(URL(string: "https://example.com")!)
/// ```
///
/// If you build your own `WKWebView` (e.g. with a custom configuration), opt in
/// before creating it:
///
/// ```swift
/// let config = WKWebViewConfiguration()
/// ProsopoProtectWebview.install(into: config)
/// let webView = WKWebView(frame: .zero, configuration: config)
/// ```
///
/// All `WKWebView` methods remain available via the ``webView`` property; this is
/// a thin owner rather than a full delegating subclass.
@MainActor
public final class ProsopoProtectWebview {

    /// The underlying `WKWebView`, with Prosopo protection already installed.
    public let webView: WKWebView

    /// Create a protected `WKWebView`.
    ///
    /// - Parameters:
    ///   - frame: The frame for the underlying `WKWebView`.
    ///   - configuration: A configuration to build on. Prosopo's user script and
    ///     message handlers are installed into it before the WebView is created.
    public init(
        frame: CGRect = .zero,
        configuration: WKWebViewConfiguration = WKWebViewConfiguration()
    ) {
        Self.install(into: configuration)
        webView = WKWebView(frame: frame, configuration: configuration)
    }

    /// Load [url] as the top-level document, attaching App Attest assertion
    /// headers to the navigation request (mirroring Android attaching headers to
    /// `loadUrl`). In-page `fetch`/`XHR` are handled separately by the injected
    /// JS shim.
    ///
    /// Assertion generation is asynchronous, so the navigation is dispatched once
    /// the headers are ready. Fail-open: if the device is not yet attested the
    /// request is loaded without assertion headers rather than being blocked.
    ///
    /// - Parameter url: The URL to load.
    public func load(_ url: URL) {
        let webView = self.webView
        Task { @MainActor in
            var request = URLRequest(url: url)
            if let headers = await ProsopoAttestIOS.shared.assertionHeaders(
                method: "GET",
                path: url.path
            ) {
                for (name, value) in headers {
                    request.setValue(value, forHTTPHeaderField: name)
                }
            }
            webView.load(request)
        }
    }

    /// Install the Prosopo JS shim and native message handlers into a
    /// `WKWebViewConfiguration`.
    ///
    /// Call this before constructing a `WKWebView` from the configuration. It is
    /// idempotent per configuration: the shim guards against double-patching, and
    /// stale handlers under the same names are removed before re-adding.
    ///
    /// - Parameter configuration: The configuration the caller will use to build a
    ///   `WKWebView`.
    public static func install(into configuration: WKWebViewConfiguration) {
        let controller = configuration.userContentController
        let bridge = ProsopoWebviewBridge()

        // Replace any previously-installed handlers so re-installing is safe.
        controller.removeScriptMessageHandler(forName: ProsopoWebviewBridge.assertionMessage)
        controller.removeScriptMessageHandler(forName: ProsopoWebviewBridge.challengeMessage)

        controller.addScriptMessageHandler(
            bridge,
            contentWorld: .page,
            name: ProsopoWebviewBridge.assertionMessage
        )
        controller.add(bridge, name: ProsopoWebviewBridge.challengeMessage)

        let script = WKUserScript(
            source: Self.shimSource,
            injectionTime: .atDocumentStart,
            forMainFrameOnly: false
        )
        controller.addUserScript(script)
    }

    /// The JavaScript shim injected at document start in every frame.
    ///
    /// It patches `fetch` and `XMLHttpRequest` so that, before each request, it
    /// asks native for fresh assertion headers (awaiting the `Promise` returned by
    /// the reply message handler) and attaches them. After each response it reads
    /// the piggybacked next-challenge header and posts it back to native.
    private static let shimSource: String = {
        let assertionMessage = ProsopoWebviewBridge.assertionMessage
        let challengeMessage = ProsopoWebviewBridge.challengeMessage
        let nextChallengeHeader = ProsopoAttestIOS.nextChallengeHeader
        return """
        (function() {
            if (window.__prosopoProtectInstalled) { return; }
            window.__prosopoProtectInstalled = true;

            function assertionHeaders(method, path) {
                try {
                    return window.webkit.messageHandlers.\(assertionMessage).postMessage({
                        method: method,
                        path: path
                    });
                } catch (e) {
                    return Promise.resolve({});
                }
            }

            function reportNextChallenge(value) {
                if (!value) { return; }
                try {
                    window.webkit.messageHandlers.\(challengeMessage).postMessage(value);
                } catch (e) {}
            }

            function pathOf(input) {
                try {
                    var raw = (typeof input === 'string') ? input : (input && input.url);
                    return new URL(raw, window.location.href).pathname;
                } catch (e) {
                    return '/';
                }
            }

            var origFetch = window.fetch;
            if (origFetch) {
                window.fetch = function(resource, init) {
                    init = init || {};
                    var method = (init.method || (resource && resource.method) || 'GET');
                    var path = pathOf(resource);
                    var self = this;
                    return assertionHeaders(method, path).then(function(h) {
                        h = h || {};
                        if (init.headers instanceof Headers) {
                            Object.keys(h).forEach(function(k) { init.headers.append(k, h[k]); });
                        } else {
                            init.headers = Object.assign({}, init.headers, h);
                        }
                        return origFetch.call(self, resource, init);
                    }).then(function(response) {
                        try { reportNextChallenge(response.headers.get('\(nextChallengeHeader)')); } catch (e) {}
                        return response;
                    });
                };
            }

            var origOpen = XMLHttpRequest.prototype.open;
            var origSend = XMLHttpRequest.prototype.send;
            XMLHttpRequest.prototype.open = function(method, url) {
                this.__prosopoMethod = method || 'GET';
                this.__prosopoPath = pathOf(url);
                return origOpen.apply(this, arguments);
            };
            XMLHttpRequest.prototype.send = function(body) {
                var self = this;
                var args = arguments;
                assertionHeaders(self.__prosopoMethod || 'GET', self.__prosopoPath || '/').then(function(h) {
                    h = h || {};
                    Object.keys(h).forEach(function(k) {
                        try { self.setRequestHeader(k, h[k]); } catch (e) {}
                    });
                    self.addEventListener('load', function() {
                        try { reportNextChallenge(self.getResponseHeader('\(nextChallengeHeader)')); } catch (e) {}
                    });
                    origSend.apply(self, args);
                });
            };
        })();
        """
    }()
}

/// Native side of the WebView bridge. Owns no WebView reference (it talks only to
/// the `ProsopoAttestIOS` singleton), so it introduces no retain cycle with the
/// content controller that holds it.
///
/// Both message-handler callbacks are invoked by WebKit on the main thread. The
/// actual assertion work is async and offloaded to a `Task`; the reply handler is
/// called back on the main actor once headers are ready.
final class ProsopoWebviewBridge: NSObject {
    /// Reply-style handler the shim awaits for per-request assertion headers.
    static let assertionMessage = "prosopoAssertion"

    /// Fire-and-forget handler the shim uses to report a piggybacked challenge.
    static let challengeMessage = "prosopoChallenge"
}

extension ProsopoWebviewBridge: WKScriptMessageHandlerWithReply {
    func userContentController(
        _ userContentController: WKUserContentController,
        didReceive message: WKScriptMessage,
        replyHandler: @escaping (Any?, String?) -> Void
    ) {
        guard message.name == Self.assertionMessage,
              let body = message.body as? [String: Any]
        else {
            // Unknown message: reply with empty headers so the page request still
            // proceeds (fail-open) rather than hanging on an unresolved Promise.
            replyHandler([String: String](), nil)
            return
        }

        let method = (body["method"] as? String) ?? "GET"
        let path = (body["path"] as? String) ?? "/"

        Task {
            let headers = await ProsopoAttestIOS.shared.assertionHeaders(method: method, path: path)
            await MainActor.run {
                replyHandler(headers ?? [String: String](), nil)
            }
        }
    }
}

extension ProsopoWebviewBridge: WKScriptMessageHandler {
    func userContentController(
        _ userContentController: WKUserContentController,
        didReceive message: WKScriptMessage
    ) {
        guard message.name == Self.challengeMessage,
              let challenge = message.body as? String
        else { return }
        ProsopoAttestIOS.shared.storeNextChallenge(challenge)
    }
}
#endif
