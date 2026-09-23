// Copyright 2021-2026 Prosopo (UK) Ltd.
// Licensed under the Apache License, Version 2.0

import Foundation
import ProsopoAttestShim

/// The three things `AppAttestManager` cannot do for itself: talk to Apple,
/// talk to Protect, and remember a key across launches.
///
/// They are protocols so the attestation lifecycle can be driven in a test.
/// Without that, the most defect-prone component in the SDK is observable only
/// on a physical device — App Attest does not exist on the Simulator or on
/// macOS, so `runAttestation` can never reach `.attested` and none of the
/// interesting paths can be entered at all. Every defect this component has had
/// was found in production for exactly that reason.
///
/// The defaults are the real implementations; shipping behaviour is unchanged.

// MARK: - Apple

/// Apple's App Attest operations.
///
/// `supportState` is `nil` when the support check itself faulted, which is not
/// the same answer as `false` — see `runAttestation`.
protocol AppAttestProviding: Sendable {
    var supportState: Bool? { get }
    func generateKey() async throws -> String
    func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data
    func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data
}

/// The real thing.
///
/// Deliberately does *not* call `DCAppAttestService` directly — every call goes
/// through `AppAttestShim`, an Objective-C frame that can catch an
/// `NSException`. Ordinary `NSError`s (including `DCError`) are forwarded
/// unchanged, so `catch let dcError as DCError` still works upstream.
struct DeviceCheckProvider: AppAttestProviding {
    var supportState: Bool? {
        AppAttestShim.supportState?.boolValue
    }

    func generateKey() async throws -> String {
        try await withCheckedThrowingContinuation { continuation in
            AppAttestShim.generateKey { keyId, error in
                if let error {
                    continuation.resume(throwing: error)
                } else if let keyId {
                    continuation.resume(returning: keyId)
                } else {
                    continuation.resume(
                        throwing: ProsopoError.attestationFailed("generateKey returned no key")
                    )
                }
            }
        }
    }

    func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            AppAttestShim.attestKey(keyId, clientDataHash: clientDataHash) { attestation, error in
                if let error {
                    continuation.resume(throwing: error)
                } else if let attestation {
                    continuation.resume(returning: attestation)
                } else {
                    continuation.resume(
                        throwing: ProsopoError.attestationFailed("attestKey returned no attestation")
                    )
                }
            }
        }
    }

    func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            AppAttestShim.generateAssertion(keyId, clientDataHash: clientDataHash) { assertion, error in
                if let error {
                    continuation.resume(throwing: error)
                } else if let assertion {
                    continuation.resume(returning: assertion)
                } else {
                    continuation.resume(
                        throwing: ProsopoError.assertionFailed("generateAssertion returned no assertion")
                    )
                }
            }
        }
    }
}

// MARK: - Protect

/// The Protect requests the attestation flow makes. `NetworkClient` is the
/// implementation; the protocol exists so a test can run the flow without a
/// server.
protocol AttestTransport: Sendable {
    func fetchChallenge(keyId: String?) async throws -> String
    func submitAttestation(
        keyId: String,
        attestationObject: Data,
        challenge: String
    ) async throws -> AttestResponse
}

extension NetworkClient: AttestTransport {}

// MARK: - Key storage

/// Where the keyId and the attested flag live between launches.
protocol KeyStore: Sendable {
    func loadKeyId() -> String?
    func isAttested() -> Bool
    func saveKeyId(_ keyId: String) -> Bool
    func markAttested() -> Bool
    func deleteAll()
}

struct KeychainStore: KeyStore {
    func loadKeyId() -> String? { KeychainManager.loadKeyId() }
    func isAttested() -> Bool { KeychainManager.isAttested() }
    func saveKeyId(_ keyId: String) -> Bool { KeychainManager.saveKeyId(keyId) }
    func markAttested() -> Bool { KeychainManager.markAttested() }
    func deleteAll() { KeychainManager.deleteAll() }
}
