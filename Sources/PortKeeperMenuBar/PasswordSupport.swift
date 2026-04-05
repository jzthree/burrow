import AppKit
import Foundation
import PortKeeperCore
import Security

struct TunnelCredentialKey: Hashable {
    let host: String
    let port: Int
    let user: String

    init?(tunnel: TunnelConfig) {
        guard let user = tunnel.user?.trimmingCharacters(in: .whitespacesAndNewlines), !user.isEmpty else {
            return nil
        }
        self.host = tunnel.host
        self.port = tunnel.sshPort
        self.user = user
    }

    var account: String {
        "\(user)@\(host):\(port)"
    }
}

enum PasswordStoreError: LocalizedError {
    case unhandled(OSStatus)

    var errorDescription: String? {
        switch self {
        case .unhandled(let status):
            return SecCopyErrorMessageString(status, nil) as String? ?? "Keychain error \(status)"
        }
    }
}

enum ConnectionPreparationError: LocalizedError {
    case cancelledPasswordPrompt

    var errorDescription: String? {
        switch self {
        case .cancelledPasswordPrompt:
            return "Password entry was cancelled."
        }
    }
}

struct PendingCredentialSave {
    let key: TunnelCredentialKey
    let password: String
}

enum CredentialSource {
    case none
    case keychain(TunnelCredentialKey)
    case prompted(TunnelCredentialKey)
}

struct ConnectionPreparation {
    let environment: [String: String]
    let pendingSave: PendingCredentialSave?
    let credentialSource: CredentialSource
}

private struct CredentialVault: Codable {
    var version: Int = 1
    var credentials: [String: String] = [:]
}

final class PasswordStore {
    private let service = "PortKeeper"
    private let vaultAccount = "__credential_vault__"

    func password(for key: TunnelCredentialKey) throws -> String? {
        try loadVault().credentials[key.account]
    }

    func save(password: String, for key: TunnelCredentialKey) throws {
        var vault = try loadVault()
        vault.credentials[key.account] = password
        try writeVault(vault)
        try? deleteLegacyPassword(for: key)
    }

    func deletePassword(for key: TunnelCredentialKey) throws {
        var vault = try loadVault()
        vault.credentials.removeValue(forKey: key.account)

        if vault.credentials.isEmpty {
            try deleteVault()
        } else {
            try writeVault(vault)
        }

        try? deleteLegacyPassword(for: key)
    }

    private func loadVault() throws -> CredentialVault {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: vaultAccount,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            guard let data = item as? Data else {
                return CredentialVault()
            }
            return try JSONDecoder().decode(CredentialVault.self, from: data)
        case errSecItemNotFound:
            return CredentialVault()
        default:
            throw PasswordStoreError.unhandled(status)
        }
    }

    private func writeVault(_ vault: CredentialVault) throws {
        let data = try JSONEncoder().encode(vault)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: vaultAccount,
        ]

        let update: [String: Any] = [
            kSecValueData as String: data,
        ]

        let status = SecItemUpdate(query as CFDictionary, update as CFDictionary)
        if status == errSecItemNotFound {
            var create = query
            create[kSecValueData as String] = data
            let addStatus = SecItemAdd(create as CFDictionary, nil)
            guard addStatus == errSecSuccess else {
                throw PasswordStoreError.unhandled(addStatus)
            }
            return
        }

        guard status == errSecSuccess else {
            throw PasswordStoreError.unhandled(status)
        }
    }

    private func deleteVault() throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: vaultAccount,
        ]

        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw PasswordStoreError.unhandled(status)
        }
    }

    private func deleteLegacyPassword(for key: TunnelCredentialKey) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key.account,
        ]

        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw PasswordStoreError.unhandled(status)
        }
    }
}

enum PasswordPrompt {
    @MainActor
    static func requestPassword(for key: TunnelCredentialKey) -> String? {
        let alert = NSAlert()
        alert.messageText = "Password Required"
        alert.informativeText = "Enter the password for \(key.user)@\(key.host):\(key.port). It will be stored in your macOS Keychain and reused for matching tunnels with the same host, port, and user."
        alert.addButton(withTitle: "Save and Connect")
        alert.addButton(withTitle: "Cancel")

        let field = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 280, height: 24))
        field.placeholderString = "Password"
        alert.accessoryView = field

        let response = alert.runModal()
        guard response == .alertFirstButtonReturn else {
            return nil
        }

        let password = field.stringValue.trimmingCharacters(in: .newlines)
        return password.isEmpty ? nil : password
    }
}

enum AskPassSupport {
    static func environment(password: String) throws -> [String: String] {
        let scriptURL = try askPassScriptURL()
        let logURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("portkeeper-askpass-\(UUID().uuidString).log")
        return [
            "SSH_ASKPASS": scriptURL.path,
            "SSH_ASKPASS_REQUIRE": "force",
            "DISPLAY": "portkeeper",
            "PORTKEEPER_PASSWORD": password,
            "PORTKEEPER_ASKPASS_LOG": logURL.path,
        ]
    }

    private static func askPassScriptURL() throws -> URL {
        let baseURL = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("PortKeeper", isDirectory: true)
            .appendingPathComponent("bin", isDirectory: true)
        try FileManager.default.createDirectory(at: baseURL, withIntermediateDirectories: true)

        let scriptURL = baseURL.appendingPathComponent("askpass.sh")
        let contents = """
        #!/bin/sh
        if [ -n "$PORTKEEPER_ASKPASS_LOG" ]; then
          printf 'askpass\\n' >> "$PORTKEEPER_ASKPASS_LOG"
        fi
        printf '%s\\n' "$PORTKEEPER_PASSWORD"
        """

        try contents.write(to: scriptURL, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: scriptURL.path)

        return scriptURL
    }
}
