// Copyright 2021-2026 Prosopo (UK) Ltd.
// Licensed under the Apache License, Version 2.0

import Foundation

// MARK: - API Request/Response types matching Protect endpoints

struct ChallengeRequest: Codable {
    let siteKey: String
    let keyId: String?

    enum CodingKeys: String, CodingKey {
        case siteKey = "site_key"
        case keyId = "key_id"
    }
}

struct ChallengeResponse: Codable {
    let challenge: String
    /// Path prefixes Protect gates for this site, as observed by the server.
    /// Optional so an older Protect server that does not send it still parses.
    let protectedRoutes: [String]?

    enum CodingKeys: String, CodingKey {
        case challenge
        case protectedRoutes = "protected_routes"
    }
}

struct AttestRequest: Codable {
    let siteKey: String
    let keyId: String
    let attestationObject: String
    let challenge: String

    enum CodingKeys: String, CodingKey {
        case siteKey = "site_key"
        case keyId = "key_id"
        case attestationObject = "attestation_object"
        case challenge
    }
}

struct AttestResponse: Codable {
    let success: Bool
    let keyId: String

    enum CodingKeys: String, CodingKey {
        case success
        case keyId = "key_id"
    }
}

struct VerifyRequest: Codable {
    let keyId: String
    let assertion: String
    let clientData: String
    let challenge: String

    enum CodingKeys: String, CodingKey {
        case keyId = "key_id"
        case assertion
        case clientData = "client_data"
        case challenge
    }
}

struct VerifyResponse: Codable {
    let decision: String
    let nextChallenge: String

    enum CodingKeys: String, CodingKey {
        case decision
        case nextChallenge = "next_challenge"
    }
}

// MARK: - Client data signed in assertions

struct AssertionClientData: Codable {
    let method: String
    let path: String
    let challenge: String
    let timestamp: String
}
