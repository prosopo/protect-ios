// Copyright 2021-2026 Prosopo (UK) Ltd.
// Licensed under the Apache License, Version 2.0

import Foundation

/// Handles HTTP communication with the Protect server for App Attest operations.
///
/// This client is used internally by the SDK and should NOT be routed through
/// `ProsopoURLProtocol` to avoid infinite recursion. It uses its own URLSession
/// with a configuration that does not have the protocol registered.
///
/// Thread-safety: all stored properties are immutable `let`s set once in `init`,
/// so a single shared instance is safe to use concurrently from any number of
/// tasks. (The previous `lazy var internalSession` was not: two concurrent
/// first-accesses could each build a session.)
final class NetworkClient: @unchecked Sendable {
    private let serverURL: URL
    private let siteKey: String

    /// Session that bypasses ProsopoURLProtocol (ephemeral) and trusts
    /// self-signed certs in development (via the shared trust delegate).
    /// Created eagerly so there is no lazy-initialisation race.
    private let internalSession: URLSession

    init(serverURL: URL, siteKey: String) {
        self.serverURL = serverURL
        self.siteKey = siteKey
        let config = URLSessionConfiguration.ephemeral
        self.internalSession = URLSession(
            configuration: config,
            delegate: ProsopoTrustDelegate(),
            delegateQueue: nil
        )
    }

    // MARK: - API Methods

    /// Fetch a new challenge from Protect.
    func fetchChallenge(keyId: String? = nil) async throws -> String {
        let url = serverURL.appendingPathComponent("/api/ios/challenge")
        let request = ChallengeRequest(siteKey: siteKey, keyId: keyId)
        let response: ChallengeResponse = try await post(url: url, body: request)
        // The challenge call is the only SDK-to-Protect request frequent
        // enough to keep this fresh: attestation happens once per key, and
        // /api/ios/verify is a Lambda-to-Protect call the device never sees.
        if let routes = response.protectedRoutes {
            ProsopoAttestIOS.shared.mergeProtectedRoutes(routes)
        }
        return response.challenge
    }

    /// Submit an attestation object for verification.
    func submitAttestation(
        keyId: String,
        attestationObject: Data,
        challenge: String
    ) async throws -> AttestResponse {
        let url = serverURL.appendingPathComponent("/api/ios/attest")
        let request = AttestRequest(
            siteKey: siteKey,
            keyId: keyId,
            attestationObject: attestationObject.base64EncodedString(),
            challenge: challenge
        )
        return try await post(url: url, body: request)
    }

    /// Verify an assertion and get a verdict + next challenge.
    func verifyAssertion(
        keyId: String,
        assertion: Data,
        clientData: Data,
        challenge: String
    ) async throws -> VerifyResponse {
        let url = serverURL.appendingPathComponent("/api/ios/verify")
        let request = VerifyRequest(
            keyId: keyId,
            assertion: assertion.base64EncodedString(),
            clientData: clientData.base64EncodedString(),
            challenge: challenge
        )
        return try await post(url: url, body: request)
    }

    // MARK: - HTTP Helpers

    private func post<T: Encodable, R: Decodable>(url: URL, body: T) async throws -> R {
        var urlRequest = URLRequest(url: url)
        urlRequest.httpMethod = "POST"
        urlRequest.setValue("application/json", forHTTPHeaderField: "Content-Type")
        urlRequest.httpBody = try JSONEncoder().encode(body)

        let (data, response) = try await internalSession.data(for: urlRequest)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw ProsopoError.networkError("Invalid response")
        }

        guard (200...299).contains(httpResponse.statusCode) else {
            let body = String(data: data, encoding: .utf8) ?? "unknown"
            throw ProsopoError.serverError(statusCode: httpResponse.statusCode, message: body)
        }

        return try JSONDecoder().decode(R.self, from: data)
    }
}

// MARK: - Shared trust delegate

/// `URLSessionDelegate` that trusts self-signed certificates in development.
///
/// Stateless and immutable, so a fresh instance can be handed to any number of
/// sessions and used concurrently. Shared by `NetworkClient` and the forwarding
/// session inside `ProsopoURLProtocol` so the trust behaviour is defined once.
///
/// In production (valid TLS certs) this delegate is never invoked.
final class ProsopoTrustDelegate: NSObject, URLSessionDelegate, @unchecked Sendable {
    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
           let serverTrust = challenge.protectionSpace.serverTrust {
            completionHandler(.useCredential, URLCredential(trust: serverTrust))
        } else {
            completionHandler(.performDefaultHandling, nil)
        }
    }
}

// MARK: - Errors

enum ProsopoError: Error, LocalizedError {
    case notConfigured
    case appAttestNotSupported
    case attestationFailed(String)
    case assertionFailed(String)
    /// Apple's DeviceCheck framework raised an Objective-C exception. Not our
    /// bug — the SDK passes requests through unsigned while it backs off, then
    /// probes the framework again.
    case deviceCheckFault(String)
    case networkError(String)
    case serverError(statusCode: Int, message: String)
    case noChallenge

    var errorDescription: String? {
        switch self {
        case .notConfigured:
            return "ProsopoAttestIOS.configure() has not been called"
        case .appAttestNotSupported:
            return "App Attest is not supported on this device"
        case .attestationFailed(let msg):
            return "Attestation failed: \(msg)"
        case .assertionFailed(let msg):
            return "Assertion failed: \(msg)"
        case .deviceCheckFault(let msg):
            return "DeviceCheck framework fault (App Attest paused, will retry): \(msg)"
        case .networkError(let msg):
            return "Network error: \(msg)"
        case .serverError(let code, let msg):
            return "Server error (\(code)): \(msg)"
        case .noChallenge:
            return "No challenge available for assertion"
        }
    }
}
