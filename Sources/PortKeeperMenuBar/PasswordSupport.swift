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

    var hostUserKey: HostUserKey {
        HostUserKey(host: host, user: user)
    }
}

struct HostUserKey: Hashable {
    let host: String
    let user: String

    var label: String {
        "\(user)@\(host)"
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
    private let service = "Burrow"
    private let legacyService = "PortKeeper"
    private let vaultAccount = "__credential_vault__"

    func password(for key: TunnelCredentialKey) throws -> String? {
        let vault = try loadVault(service: service)
        if let password = vault.credentials[key.account] {
            return password
        }
        return try loadVault(service: legacyService).credentials[key.account]
    }

    func save(password: String, for key: TunnelCredentialKey) throws {
        var vault = try loadVault(service: service)
        vault.credentials[key.account] = password
        try writeVault(vault)
        try? deleteLegacyPassword(for: key)
    }

    func deletePassword(for key: TunnelCredentialKey) throws {
        var vault = try loadVault(service: service)
        vault.credentials.removeValue(forKey: key.account)

        if vault.credentials.isEmpty {
            try deleteVault()
        } else {
            try writeVault(vault)
        }

        try? deleteLegacyPassword(for: key)
    }

    private func loadVault(service: String) throws -> CredentialVault {
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
            kSecAttrService as String: legacyService,
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
    static func requestPassword(for key: TunnelCredentialKey, tunnelName: String?, retry: Bool) -> String? {
        let alert = NSAlert()
        let endpoint = "\(key.user)@\(key.host):\(key.port)"
        let tunnelSuffix = tunnelName.map { " (tunnel: \($0))" } ?? ""

        if retry {
            alert.messageText = "Wrong SSH password for \(endpoint)"
            alert.informativeText = "The previous password was rejected by the remote SSH server\(tunnelSuffix).\n\nEnter the SSH password for the remote host \(key.host) (the one you'd type into `ssh \(key.user)@\(key.host)`).\n\nThis is NOT your Mac login password."
            alert.alertStyle = .warning
        } else {
            alert.messageText = "SSH password for \(endpoint)"
            alert.informativeText = "Burrow is opening an SSH tunnel\(tunnelSuffix) and the remote server is asking for a password.\n\nEnter the SSH password for the remote host \(key.host) (the one you'd type into `ssh \(key.user)@\(key.host)`).\n\nThis is NOT your Mac login password.\n\nIt will be stored in your macOS Keychain and reused for any tunnel that connects to \(key.user)@\(key.host)."
        }

        alert.addButton(withTitle: "Save and Connect")
        alert.addButton(withTitle: "Cancel")

        let field = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 320, height: 24))
        field.placeholderString = "Remote SSH password for \(key.user)@\(key.host)"
        alert.accessoryView = field
        alert.window.initialFirstResponder = field

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
            .appendingPathComponent("burrow-askpass-\(UUID().uuidString).log")
        return [
            "SSH_ASKPASS": scriptURL.path,
            "SSH_ASKPASS_REQUIRE": "force",
            "DISPLAY": "burrow",
            "BURROW_PASSWORD": password,
            "BURROW_ASKPASS_LOG": logURL.path,
            "PORTKEEPER_PASSWORD": password,
            "PORTKEEPER_ASKPASS_LOG": logURL.path,
        ]
    }

    private static func askPassScriptURL() throws -> URL {
        let baseURL = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Burrow", isDirectory: true)
            .appendingPathComponent("bin", isDirectory: true)
        try FileManager.default.createDirectory(at: baseURL, withIntermediateDirectories: true)

        let scriptURL = baseURL.appendingPathComponent("askpass.sh")
        let contents = """
        #!/bin/sh
        LOG_PATH="${BURROW_ASKPASS_LOG:-$PORTKEEPER_ASKPASS_LOG}"
        PASSWORD="${BURROW_PASSWORD:-$PORTKEEPER_PASSWORD}"
        if [ -n "$LOG_PATH" ]; then
          printf 'askpass\\n' >> "$LOG_PATH"
        fi
        printf '%s\\n' "$PASSWORD"
        """

        try contents.write(to: scriptURL, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: scriptURL.path)

        return scriptURL
    }
}
