// Copyright 2021-2026 Prosopo (UK) Ltd.
// Licensed under the Apache License, Version 2.0

import Foundation
import Security

/// Manages persistent storage of App Attest key identifiers in the iOS Keychain.
///
/// The keyId must survive app restarts (but not reinstalls), and the Keychain
/// is the appropriate storage mechanism for cryptographic key references.
enum KeychainManager {
    private static let service = "io.prosopo.protect"
    private static let keyIdAccount = "appattest-key-id"
    private static let attestedAccount = "appattest-attested"

    /// Save the App Attest key identifier to the Keychain.
    static func saveKeyId(_ keyId: String) -> Bool {
        guard let data = keyId.data(using: .utf8) else { return false }

        // Delete any existing entry first
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: keyIdAccount,
        ]
        SecItemDelete(deleteQuery as CFDictionary)

        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: keyIdAccount,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]

        let status = SecItemAdd(addQuery as CFDictionary, nil)
        if status != errSecSuccess {
            ProsopoLogger.error("Failed to save keyId to Keychain: \(status)")
        }
        return status == errSecSuccess
    }

    /// Load the App Attest key identifier from the Keychain.
    static func loadKeyId() -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: keyIdAccount,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess,
              let data = result as? Data,
              let keyId = String(data: data, encoding: .utf8)
        else {
            return nil
        }

        return keyId
    }

    /// Mark this device as attested in the Keychain.
    static func markAttested() -> Bool {
        guard let data = "true".data(using: .utf8) else { return false }

        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: attestedAccount,
        ]
        SecItemDelete(deleteQuery as CFDictionary)

        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: attestedAccount,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]

        let status = SecItemAdd(addQuery as CFDictionary, nil)
        return status == errSecSuccess
    }

    /// Check if this device has been attested.
    static func isAttested() -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: attestedAccount,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        return status == errSecSuccess
    }

    /// Delete all Prosopo Keychain entries (used on re-attestation).
    static func deleteAll() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
        ]
        SecItemDelete(query as CFDictionary)
    }

    /// On iOS, Keychain items with `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`
    /// are not reliably wiped when the app is uninstalled — they can linger and
    /// cause a fresh install to pick up a stale App Attest keyId that the server
    /// has no record of. `UserDefaults`, unlike the Keychain, is app-sandboxed
    /// and *is* wiped on uninstall. Use a flag there to detect a fresh install
    /// and clear any orphaned Keychain entries before attestation runs.
    static func wipeIfFreshInstall() {
        let flagKey = "io.prosopo.protect.installFlag"
        let defaults = UserDefaults.standard
        guard !defaults.bool(forKey: flagKey) else { return }
        ProsopoLogger.info("Fresh install detected — clearing stale Keychain entries")
        deleteAll()
        defaults.set(true, forKey: flagKey)
    }
}
