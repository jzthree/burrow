import Foundation
import LocalAuthentication
import PortKeeperCore
import Security

enum TwoFactorStoreError: LocalizedError {
    case parseFailed
    case biometricsUnavailable(String)
    case keychain(OSStatus)
    case cancelled

    var errorDescription: String? {
        switch self {
        case .parseFailed:
            return "That doesn't look like a valid authenticator secret (expected an otpauth:// URI or a base32 key)."
        case .biometricsUnavailable(let detail):
            return "Touch ID isn't available: \(detail)"
        case .keychain(let status):
            let message = SecCopyErrorMessageString(status, nil) as String? ?? "OSStatus \(status)"
            return "Keychain error: \(message)"
        case .cancelled:
            return "Touch ID was cancelled."
        }
    }
}

/// Stores TOTP seeds in the login Keychain and gates every reveal behind a
/// LocalAuthentication (Touch ID) check.
///
/// Why not a biometric Keychain ACL (`SecAccessControlCreateWithFlags`)? On
/// macOS those items require the data-protection keychain, which needs a
/// `keychain-access-groups` entitlement — and that entitlement is
/// profile-restricted, so a locally Development-signed app fails to launch with
/// it (launchd POSIX 163). Gating with LAContext keeps the same one-tap UX,
/// needs no entitlement, and matches how the password store uses the Keychain.
struct TwoFactorStore {
    private let service = "Burrow-2FA"

    private func baseQuery(account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
    }

    static func biometricsAvailable() -> Bool {
        var error: NSError?
        return LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    }

    /// Parses an otpauth URI or base32 secret and stores the raw key bytes.
    /// Returns the parsed params (digits/period/algorithm) for the config.
    @discardableResult
    func enroll(secretInput: String, account: String) throws -> TOTPSecret {
        guard let parsed = TOTPSecret.parse(secretInput) else {
            throw TwoFactorStoreError.parseFailed
        }
        try storeSecretBytes(parsed.secret, account: account)
        return parsed
    }

    func storeSecretBytes(_ data: Data, account: String) throws {
        SecItemDelete(baseQuery(account: account) as CFDictionary)
        var add = baseQuery(account: account)
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw TwoFactorStoreError.keychain(status)
        }
    }

    func hasSecret(account: String) -> Bool {
        var query = baseQuery(account: account)
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        return SecItemCopyMatching(query as CFDictionary, nil) == errSecSuccess
    }

    /// Presents the Touch ID sheet, then reads the seed and returns the current
    /// code. Throws `.cancelled` if the user dismisses Touch ID.
    func currentCode(for account: TwoFactorAccount, reason: String, at date: Date = Date()) async throws -> String {
        try await authenticate(reason: reason)
        let bytes = try readSecretBytes(account: account.name)
        let secret = TOTPSecret(
            secret: bytes,
            digits: account.digits,
            period: account.period,
            algorithm: account.totpAlgorithm
        )
        return TOTPGenerator.code(for: secret, at: date)
    }

    private func authenticate(reason: String) async throws {
        let context = LAContext()
        var policyError: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &policyError) else {
            throw TwoFactorStoreError.biometricsUnavailable(policyError?.localizedDescription ?? "unavailable")
        }
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { success, _ in
                if success {
                    continuation.resume()
                } else {
                    continuation.resume(throwing: TwoFactorStoreError.cancelled)
                }
            }
        }
    }

    private func readSecretBytes(account: String) throws -> Data {
        var query = baseQuery(account: account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data else {
            throw TwoFactorStoreError.keychain(status)
        }
        return data
    }

    func delete(account: String) {
        SecItemDelete(baseQuery(account: account) as CFDictionary)
    }
}
