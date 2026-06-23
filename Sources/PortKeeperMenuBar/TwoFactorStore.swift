import Foundation
import LocalAuthentication
import PortKeeperCore
import Security

enum TwoFactorStoreError: LocalizedError {
    case parseFailed
    case authenticationUnavailable(String)
    case keychain(OSStatus)
    case cancelled

    var errorDescription: String? {
        switch self {
        case .parseFailed:
            return "That doesn't look like a valid authenticator secret (expected an otpauth:// URI or a base32 key)."
        case .authenticationUnavailable(let detail):
            return "Mac authentication isn't available: \(detail)"
        case .keychain(let status):
            let message = SecCopyErrorMessageString(status, nil) as String? ?? "OSStatus \(status)"
            return "Keychain error: \(message)"
        case .cancelled:
            return "Mac authentication was cancelled."
        }
    }
}

/// Stores TOTP seeds in the login Keychain and gates every reveal behind a
/// LocalAuthentication check.
///
/// Why not a biometric Keychain ACL (`SecAccessControlCreateWithFlags`)? On
/// macOS those items require the data-protection keychain, which needs a
/// `keychain-access-groups` entitlement — and that entitlement is
/// profile-restricted, so a locally Development-signed app fails to launch with
/// it (launchd POSIX 163). Gating with LAContext keeps the same one-tap UX,
/// needs no entitlement, and matches how the password store uses the Keychain.
@MainActor
final class TwoFactorStore {
    private let service = "Burrow-2FA"
    private struct CachedSecret {
        let data: Data
        let expiresAt: Date
    }
    private var cachedSecrets: [String: CachedSecret] = [:]

    private func baseQuery(account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
    }

    static func authenticationAvailable() -> Bool {
        var error: NSError?
        return LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: &error)
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
        cachedSecrets[account] = nil
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

    /// Presents the Mac authentication sheet, then reads the seed and returns
    /// the current code. Throws `.cancelled` if the user dismisses it.
    func currentCode(
        for account: TwoFactorAccount,
        reason: String,
        at date: Date = Date(),
        unlockCacheSeconds: Int = 0
    ) async throws -> String {
        let bytes = try await secretBytes(
            account: account.name,
            reason: reason,
            unlockCacheSeconds: unlockCacheSeconds
        )
        let secret = TOTPSecret(
            secret: bytes,
            digits: account.digits,
            period: account.period,
            algorithm: account.totpAlgorithm
        )
        return TOTPGenerator.code(for: secret, at: date)
    }

    /// Authenticates once, then returns codes for this TOTP period and the next.
    func currentAndNextCodes(
        for account: TwoFactorAccount,
        reason: String,
        at date: Date = Date(),
        unlockCacheSeconds: Int = 0
    ) async throws -> (current: String, next: String, periodEnd: Date) {
        let bytes = try await secretBytes(
            account: account.name,
            reason: reason,
            unlockCacheSeconds: unlockCacheSeconds
        )
        let secret = TOTPSecret(
            secret: bytes,
            digits: account.digits,
            period: account.period,
            algorithm: account.totpAlgorithm
        )
        let period = max(1, account.period)
        let periodSeconds = Double(period)
        let remainder = date.timeIntervalSince1970.truncatingRemainder(dividingBy: periodSeconds)
        let periodEnd = date.addingTimeInterval(periodSeconds - remainder)
        return (
            current: TOTPGenerator.code(for: secret, at: date),
            next: TOTPGenerator.code(for: secret, at: periodEnd.addingTimeInterval(1)),
            periodEnd: periodEnd
        )
    }

    func clearCache() {
        cachedSecrets.removeAll()
    }

    private func secretBytes(
        account: String,
        reason: String,
        unlockCacheSeconds: Int
    ) async throws -> Data {
        let now = Date()
        let cacheSeconds = max(0, unlockCacheSeconds)
        if cacheSeconds > 0,
           let cached = cachedSecrets[account],
           cached.expiresAt > now {
            return cached.data
        }

        try await authenticate(reason: reason)
        let bytes = try readSecretBytes(account: account)
        if cacheSeconds > 0 {
            cachedSecrets[account] = CachedSecret(
                data: bytes,
                expiresAt: now.addingTimeInterval(TimeInterval(cacheSeconds))
            )
        } else {
            cachedSecrets[account] = nil
        }
        return bytes
    }

    private func authenticate(reason: String) async throws {
        let context = LAContext()
        var policyError: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &policyError) else {
            throw TwoFactorStoreError.authenticationUnavailable(policyError?.localizedDescription ?? "unavailable")
        }
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, _ in
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
        cachedSecrets[account] = nil
        SecItemDelete(baseQuery(account: account) as CFDictionary)
    }
}
