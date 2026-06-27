import AppKit
import Foundation
import PortKeeperCore
import Security

struct TunnelCredentialKey: Hashable {
    let host: String
    let port: Int
    let user: String

    init(host: String, port: Int, user: String) {
        self.host = host
        self.port = port
        self.user = user
    }

    init?(gateway: GatewayConfig) {
        guard let user = gateway.user?.trimmingCharacters(in: .whitespacesAndNewlines), !user.isEmpty else {
            return nil
        }
        // 443 = the TLS port openconnect VPNs answer on; keeps the keychain
        // account label meaningful ("user@vpn.host:443").
        self.host = gateway.server
        self.port = 443
        self.user = user
    }

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
    case missingSavedPassword(String)

    var errorDescription: String? {
        switch self {
        case .cancelledPasswordPrompt:
            return "Password entry was cancelled."
        case .missingSavedPassword(let endpoint):
            return "No saved SSH password for \(endpoint). Start manually to enter it."
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

struct PreloadedPasswords {
    private let credentials: [String: String]

    init(credentials: [String: String]) {
        self.credentials = credentials
    }

    func password(for key: TunnelCredentialKey) -> String? {
        credentials[key.account]
    }
}

final class PasswordStore {
    private let service = "Burrow"
    private let legacyService = "PortKeeper"
    private let vaultAccount = "__credential_vault__"

    func password(for key: TunnelCredentialKey) throws -> String? {
        try preloadPasswords(for: [key]).password(for: key)
    }

    func preloadPasswords(for keys: Set<TunnelCredentialKey>) throws -> PreloadedPasswords {
        var credentials = try loadVault(service: legacyService).credentials
        credentials.merge(try loadVault(service: service).credentials) { _, current in current }

        for key in keys where credentials[key.account] == nil {
            if let password = try loadSinglePassword(service: service, account: key.account) {
                credentials[key.account] = password
                continue
            }

            if let password = try loadSinglePassword(service: legacyService, account: key.account) {
                credentials[key.account] = password
            }
        }

        return PreloadedPasswords(credentials: credentials)
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

    private func loadSinglePassword(service: String, account: String) throws -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            guard let data = item as? Data else {
                return nil
            }
            return String(data: data, encoding: .utf8)
        case errSecItemNotFound:
            return nil
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
    static func requestVPNPassword(gatewayName: String, server: String, user: String, retry: Bool) -> String? {
        let alert = NSAlert()
        if retry {
            alert.messageText = "Wrong VPN password for \(user)@\(server)"
            alert.informativeText = "The previous password was rejected by the VPN gateway (Burrow gateway: \(gatewayName)).\n\nEnter the VPN password you use with the official client for \(server)."
            alert.alertStyle = .warning
        } else {
            alert.messageText = "VPN password for \(user)@\(server)"
            alert.informativeText = "Burrow is connecting the VPN gateway “\(gatewayName)” with openconnect.\n\nEnter the VPN password you use with the official client for \(server). If your login needs a second factor (e.g. Duo), approve it when prompted on your device.\n\nThe password is stored in your macOS Keychain after the first successful connection."
        }

        alert.addButton(withTitle: "Connect")
        alert.addButton(withTitle: "Cancel")

        let field = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 320, height: 24))
        field.placeholderString = "VPN password for \(user)@\(server)"
        alert.accessoryView = field
        alert.window.initialFirstResponder = field

        let response = alert.runModal()
        guard response == .alertFirstButtonReturn else {
            return nil
        }

        let password = field.stringValue.trimmingCharacters(in: .newlines)
        return password.isEmpty ? nil : password
    }

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

enum SSHHostPrompt {
    @MainActor
    static func request() -> SSHConfigWriter.HostEntry? {
        let alert = NSAlert()
        alert.messageText = "New SSH Host"
        alert.informativeText = "Adds a Host entry to your ~/.ssh/config so you can open it from Burrow and from any terminal. Burrow only appends; it won't change your existing config."

        let width: CGFloat = 360
        let container = NSStackView(frame: NSRect(x: 0, y: 0, width: width, height: 116))
        container.orientation = .vertical
        container.alignment = .leading
        container.spacing = 6

        let aliasField = NSTextField(frame: NSRect(x: 0, y: 0, width: width, height: 24))
        aliasField.placeholderString = "Name / alias (e.g. lab-gpu)"
        let hostField = NSTextField(frame: NSRect(x: 0, y: 0, width: width, height: 24))
        hostField.placeholderString = "Host address (e.g. gpu.lab.edu or 10.0.0.5)"
        let userField = NSTextField(frame: NSRect(x: 0, y: 0, width: width, height: 24))
        userField.placeholderString = "User (optional)"
        let portField = NSTextField(frame: NSRect(x: 0, y: 0, width: width, height: 24))
        portField.placeholderString = "Port (optional, default 22)"

        for field in [aliasField, hostField, userField, portField] {
            field.translatesAutoresizingMaskIntoConstraints = false
            field.widthAnchor.constraint(equalToConstant: width).isActive = true
            container.addArrangedSubview(field)
        }
        alert.accessoryView = container
        alert.window.initialFirstResponder = aliasField

        alert.addButton(withTitle: "Add to ~/.ssh/config")
        alert.addButton(withTitle: "Cancel")

        guard alert.runModal() == .alertFirstButtonReturn else {
            return nil
        }
        let alias = aliasField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        let host = hostField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        let user = userField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        let port = Int(portField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines))
        guard !alias.isEmpty, !host.isEmpty else {
            return nil
        }
        return SSHConfigWriter.HostEntry(
            alias: alias,
            hostName: host,
            user: user.isEmpty ? nil : user,
            port: port
        )
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

    /// Askpass env for warming a host: answers password prompts with `password`
    /// (if any) and 2FA / one-time-code prompts with `otpCode`. Used for the
    /// no-tty `ssh -fN` warm connection, where SSH_ASKPASS_REQUIRE=force routes
    /// keyboard-interactive prompts through the helper.
    static func warmEnvironment(password: String?, otpCode: String?) throws -> [String: String] {
        let scriptURL = try promptAwareScriptURL()
        var env: [String: String] = [
            "SSH_ASKPASS": scriptURL.path,
            "SSH_ASKPASS_REQUIRE": "force",
            "DISPLAY": "burrow",
        ]
        if let password { env["BURROW_PASSWORD"] = password }
        if let otpCode { env["BURROW_OTP_CODE"] = otpCode }
        return env
    }

    private static func askPassScriptURL() throws -> URL {
        let scriptURL = try binDirectory().appendingPathComponent("askpass.sh")
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

    private static func promptAwareScriptURL() throws -> URL {
        let scriptURL = try binDirectory().appendingPathComponent("askpass-warm.sh")
        // $1 is the prompt text. Code-ish prompts get the OTP; everything else
        // gets the password. Falls back to the other value if one is empty.
        let contents = """
        #!/bin/sh
        prompt=$(printf '%s' "$1" | tr 'A-Z' 'a-z')
        case "$prompt" in
          *verification*code*|*one-time*|*one\\ time*|*token*|*passcode*|*otp*|*duo*|*authenticator*|*2fa*)
            if [ -n "$BURROW_OTP_CODE" ]; then printf '%s\\n' "$BURROW_OTP_CODE"; else printf '%s\\n' "$BURROW_PASSWORD"; fi
            ;;
          *)
            if [ -n "$BURROW_PASSWORD" ]; then printf '%s\\n' "$BURROW_PASSWORD"; else printf '%s\\n' "$BURROW_OTP_CODE"; fi
            ;;
        esac
        """
        try contents.write(to: scriptURL, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: scriptURL.path)
        return scriptURL
    }

    private static func binDirectory() throws -> URL {
        let baseURL = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Burrow", isDirectory: true)
            .appendingPathComponent("bin", isDirectory: true)
        try FileManager.default.createDirectory(at: baseURL, withIntermediateDirectories: true)
        return baseURL
    }
}
