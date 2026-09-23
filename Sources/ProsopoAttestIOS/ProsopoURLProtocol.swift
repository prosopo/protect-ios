// Copyright 2021-2026 Prosopo (UK) Ltd.
// Licensed under the Apache License, Version 2.0

import Foundation

/// A URLProtocol subclass that transparently adds App Attest assertion
/// headers to outgoing HTTP requests.
///
/// When registered via `URLProtocol.registerClass`, this intercepts all
/// requests made through `URLSession.shared` (and sessions using the
/// `.default` configuration).
///
/// For apps using a custom `URLSession` — including any framework that builds
/// its own session, like Alamofire's `Session(configuration:)` — global
/// registration does *not* apply. The protocol class must be added to the
/// `URLSessionConfiguration.protocolClasses` array before the session is
/// built. The class is exposed publicly for that purpose:
///
/// ```swift
/// let config = URLSessionConfiguration.default
/// config.protocolClasses = [ProsopoURLProtocol.self] + (config.protocolClasses ?? [])
/// let session = Session(configuration: config)  // Alamofire
/// ```
///
/// It skips:
/// - Requests already handled (prevents infinite recursion)
/// - Requests to the Protect server itself
/// - Requests when the device is not yet attested (fail-open)
///
/// Failing open is not the end of the story, because the edge default-denies an
/// unsigned cookie-less JSON request. When that happens the response is a
/// deferral rather than a refusal, and this protocol answers it the way
/// protect.js answers it on the web: attest, then send the request again.
public final class ProsopoURLProtocol: URLProtocol {

    /// Key used to mark requests as already handled.
    private static let handledKey = "io.prosopo.protect.handled"

    /// The internal session used to forward the modified request.
    /// Uses ephemeral config so it doesn't trigger this protocol again.
    /// This `URLProtocol` instance handles exactly one request, so the lazy
    /// initialiser is only ever touched by one thread — no race here.
    private lazy var internalSession: URLSession = {
        let config = URLSessionConfiguration.ephemeral
        return URLSession(configuration: config, delegate: ProsopoTrustDelegate(), delegateQueue: nil)
    }()

    private var dataTask: URLSessionDataTask?

    // MARK: - URLProtocol overrides

    public override class func canInit(with request: URLRequest) -> Bool {
        // Don't handle requests we've already processed
        guard URLProtocol.property(forKey: handledKey, in: request) == nil else {
            return false
        }

        // Check if this request should be intercepted
        return ProsopoAttestIOS.shared.shouldIntercept(request)
    }

    public override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        request
    }

    public override func startLoading() {
        Task { await self.load(allowReplay: true) }
    }

    public override func stopLoading() {
        dataTask?.cancel()
    }

    // MARK: - Request lifecycle

    /// Mint assertion headers off the main thread, attach them if we got any,
    /// then send.
    ///
    /// `allowReplay` is false on the second pass, so a deferral can only ever
    /// cost one extra round trip.
    private func load(allowReplay: Bool, forceSign: Bool = false) async {
        let prosopo = ProsopoAttestIOS.shared
        let method = request.httpMethod ?? "GET"
        let path = request.url?.path ?? "/"

        guard let outgoing = handledCopyOfRequest() else {
            failWithUnmarkableRequest()
            return
        }

        // The shared helper handles the not-attested / failure cases (returning
        // nil), the attestation retry nudge and the re-attest recovery, so this
        // transport only has to attach + forward.
        if let headers = await prosopo.assertionHeaders(
            method: method, path: path, forceSign: forceSign
        ) {
            for (name, value) in headers {
                outgoing.setValue(value, forHTTPHeaderField: name)
            }
            ProsopoLogger.debug("Attached assertion headers to \(method) \(path)")
        } else if let operation = AppAttestManager.deviceCheckFaultOperation {
            // Once the exception barrier stops DeviceCheck faults from crashing
            // the app, they also stop showing up in the host app's crash
            // reporter — which was our only sight of them. Tag the fail-open
            // request so the fault is still countable server-side, and we can
            // tell "fixed" from "merely silent". Only set while a fault is live,
            // so ordinary not-yet-attested traffic isn't tagged.
            outgoing.setValue(operation.rawValue, forHTTPHeaderField: "X-Prosopo-Attest-Fault")
        }

        send(outgoing, allowReplay: allowReplay)
    }

    private func send(_ outgoing: NSMutableURLRequest, allowReplay: Bool) {
        let path = outgoing.url?.path ?? "/"

        dataTask = internalSession.dataTask(with: outgoing as URLRequest) { data, response, error in
            if let error = error {
                self.client?.urlProtocol(self, didFailWithError: error)
                return
            }

            if allowReplay, self.isReplayableDeferral(response) {
                ProsopoLogger.warning(
                    "Edge deferred \(path) for want of a session — attesting and replaying once"
                )
                Task { await self.replay() }
                return
            }

            if let response = response {
                // Extract piggybacked next challenge from response headers
                if let httpResponse = response as? HTTPURLResponse,
                   let nextChallenge = httpResponse.value(forHTTPHeaderField: ProsopoAttestIOS.nextChallengeHeader) {
                    ProsopoAttestIOS.shared.storeNextChallenge(nextChallenge)
                }

                self.client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            }

            if let data = data {
                self.client?.urlProtocol(self, didLoad: data)
            }

            self.client?.urlProtocolDidFinishLoading(self)
        }
        dataTask?.resume()
    }

    /// Wait for attestation, then send the request again — signed, if the wait
    /// produced a key.
    ///
    /// Worth doing even when it doesn't: the cost is one request, and the
    /// alternative is handing the app a 401 it has no way to act on.
    private func replay() async {
        // The edge deferring this request is proof the route is protected,
        // whatever the route filter believed a moment ago. Record it so the
        // next request to it is signed first time, and sign this one.
        ProsopoAttestIOS.shared.learnProtectedRoute(path: request.url?.path ?? "/")
        await ProsopoAttestIOS.shared.attestForDeferredRequest()
        await load(allowReplay: false, forceSign: true)
    }

    /// A deferral we can actually do something about.
    ///
    /// A streamed body is excluded: `URLProtocol` hands the stream over once, so
    /// a replay would send an empty body rather than the caller's.
    private func isReplayableDeferral(_ response: URLResponse?) -> Bool {
        guard request.httpBodyStream == nil else { return false }
        return ProsopoAttestIOS.isSessionDeferral(response)
    }

    // MARK: - Helpers

    /// A mutable copy of the request, marked as already handled by this
    /// protocol.
    ///
    /// The mark is what stops `URLProtocol` picking the request up again and
    /// recursing, so a request that cannot be marked must not be sent at all --
    /// hence the optional rather than a force cast. `mutableCopy()` on
    /// `NSURLRequest` is documented to return an `NSMutableURLRequest`, so nil
    /// here means Foundation broke its own contract; the point is that the
    /// failure is a returned error rather than a trap or an infinite loop.
    private func handledCopyOfRequest() -> NSMutableURLRequest? {
        guard let mutableRequest = (request as NSURLRequest).mutableCopy() as? NSMutableURLRequest else {
            return nil
        }
        URLProtocol.setProperty(true, forKey: Self.handledKey, in: mutableRequest)
        return mutableRequest
    }

    /// Report the failure of `handledCopyOfRequest()` to the client.
    ///
    /// Deliberately not fail-open: forwarding an unmarked request would be
    /// picked up by this protocol again and loop.
    private func failWithUnmarkableRequest() {
        ProsopoLogger.error("Could not take a mutable copy of the request; failing it rather than looping")
        client?.urlProtocol(self, didFailWithError: ProsopoError.networkError("could not copy request"))
    }
}
