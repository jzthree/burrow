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

        // ThisDeviceOnly keeps the vault out of anything that leaves this Mac
        // (Migration Assistant, backups) — matching the 2FA seed store.
        // Included in the update too, so pre-existing vaults are upgraded on
        // their next save.
        let update: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]

        let status = SecItemUpdate(query as CFDictionary, update as CFDictionary)
        if status == errSecItemNotFound {
            var create = query
            create[kSecValueData as String] = data
            create[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
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

enum WarmSignInPrompt {
    struct Result {
        let code: String?
        let password: String?
        /// The user chose "Send Duo Push" — answer the Duo device menu with the
        /// push option and wait for phone approval instead of a typed code.
        let sendDuoPush: Bool
    }


    /// The last few prompt lines, clipped for the dialog's prompt box. A Duo
    /// device menu arrives as several lines; the tail is the current state.
    fileprivate static func renderedPrompts(_ prompts: [String]) -> String? {
        let lines = prompts.suffix(6).map { prompt -> String in
            prompt.count > 160 ? "\(prompt.prefix(160))…" : prompt
        }
        return lines.isEmpty ? nil : lines.joined(separator: "\n")
    }

    fileprivate static func looksLikeCodePrompt(_ prompt: String) -> Bool {
        let lowered = prompt.lowercased()
        return ["verification code", "one-time", "one time", "token", "passcode", "otp", "authenticator", "2fa"]
            .contains { lowered.contains($0) }
    }

    fileprivate static func looksLikeDuoMenu(_ prompt: String) -> Bool {
        let lowered = prompt.lowercased()
        return lowered.contains("duo") || (lowered.contains("option") && lowered.contains("1."))
    }
}

private final class ClosureTarget: NSObject {
    let action: () -> Void
    init(_ action: @escaping () -> Void) { self.action = action }
    @objc func fire() { action() }
}

/// A non-modal sign-in window for warming a host. Unlike the old app-modal
/// `NSAlert.runModal()`, this floats without blocking the app, so the menu
/// stays usable and the host row can bring the window back to the front while
/// a sign-in is pending. One controller per in-flight sign-in; it resolves its
/// completion exactly once (a typed answer, a Duo push, or cancel/close).
@MainActor
final class WarmSignInWindowController: NSObject, NSWindowDelegate {
    private var window: NSWindow?
    private var completion: ((WarmSignInPrompt.Result?) -> Void)?
    private var codeField: NSTextField?
    private var passwordField: NSSecureTextField?
    private var buttonTargets: [ClosureTarget] = []
    private var resolved = false

    func present(
        alias: String,
        host: String,
        retry: Bool,
        reason: String?,
        serverPrompts: [String],
        linkedAccountName: String?,
        availableCode: String?,
        completion: @escaping (WarmSignInPrompt.Result?) -> Void
    ) {
        self.completion = completion
        let content = makeContentView(
            alias: alias, host: host, retry: retry, reason: reason,
            serverPrompts: serverPrompts, linkedAccountName: linkedAccountName,
            availableCode: availableCode
        )
        let hosting = NSViewController()
        hosting.view = content
        let window = NSWindow(contentViewController: hosting)
        window.styleMask = [.titled, .closable]
        window.title = retry ? "Try \(alias) again" : "Sign in to keep \(alias) warm"
        window.isReleasedWhenClosed = false
        window.level = .floating
        window.delegate = self
        window.setContentSize(content.fittingSize)
        window.center()
        self.window = window
        focus()
        // Land the cursor in the field the host's prompt points at.
        let asksCode = serverPrompts.contains(where: WarmSignInPrompt.looksLikeCodePrompt)
        let asksDuoMenu = serverPrompts.contains(where: WarmSignInPrompt.looksLikeDuoMenu)
        let asksPassword = serverPrompts.contains {
            let lowered = $0.lowercased()
            return lowered.contains("password") || lowered.contains("passphrase")
        }
        window.initialFirstResponder = (asksPassword && !asksCode && !asksDuoMenu) ? passwordField : codeField
    }

    /// Bring the pending sign-in window back to the front — the action behind
    /// clicking a host row that is mid-sign-in.
    func focus() {
        guard let window else { return }
        NSApp.activate(ignoringOtherApps: true)
        window.makeKeyAndOrderFront(nil)
    }

    private func resolve(_ result: WarmSignInPrompt.Result?) {
        guard !resolved else { return }
        resolved = true
        let completion = self.completion
        self.completion = nil
        window?.delegate = nil
        window?.close()
        window = nil
        completion?(result)
    }

    func windowWillClose(_ notification: Notification) {
        // A close with no button press is a cancel.
        resolve(nil)
    }

    private func makeContentView(
        alias: String, host: String, retry: Bool, reason: String?,
        serverPrompts: [String], linkedAccountName: String?, availableCode: String?
    ) -> NSView {
        let width: CGFloat = 340
        let root = NSStackView()
        root.orientation = .vertical
        root.alignment = .leading
        root.spacing = 10
        root.edgeInsets = NSEdgeInsets(top: 18, left: 20, bottom: 16, right: 20)
        root.translatesAutoresizingMaskIntoConstraints = false

        let title = NSTextField(labelWithString: retry ? "That didn’t work — try \(alias) again" : "Sign in to keep \(alias) warm")
        title.font = .systemFont(ofSize: 14, weight: .semibold)
        root.addArrangedSubview(title)

        let informativeText: String
        if retry {
            let detail = reason.map { "\($0.prefix(1).capitalized)\($0.dropFirst())." } ?? "The previous attempt was rejected."
            informativeText = "\(detail)\n\nAnswer the host's prompt below with fresh values — codes expire quickly. Entries are used once and not stored."
        } else {
            informativeText = serverPrompts.isEmpty
                ? "Burrow is opening a persistent SSH connection to \(host). Depending on the host, it may ask for a password, a 2FA code, or a Duo push. Entries are used once and not stored."
                : "Burrow is opening a persistent SSH connection to \(host). Answer what it asked below. Entries are used once and not stored."
        }
        let informative = NSTextField(wrappingLabelWithString: informativeText)
        informative.font = .systemFont(ofSize: 11.5)
        informative.textColor = .secondaryLabelColor
        informative.translatesAutoresizingMaskIntoConstraints = false
        informative.widthAnchor.constraint(equalToConstant: width).isActive = true
        root.addArrangedSubview(informative)

        // The server's prompt is the headline: a caption plus the host's literal
        // words in a bordered, terminal-style box.
        if let promptText = WarmSignInPrompt.renderedPrompts(serverPrompts) {
            let caption = NSTextField(labelWithString: "\(host) asked:")
            caption.font = .systemFont(ofSize: 11, weight: .semibold)
            caption.textColor = .secondaryLabelColor
            root.addArrangedSubview(caption)

            let promptLabel = NSTextField(wrappingLabelWithString: promptText)
            promptLabel.font = .monospacedSystemFont(ofSize: 11.5, weight: .regular)
            promptLabel.isSelectable = true
            promptLabel.translatesAutoresizingMaskIntoConstraints = false

            let box = NSView()
            box.wantsLayer = true
            box.layer?.cornerRadius = 6
            box.layer?.borderWidth = 1
            box.layer?.borderColor = NSColor.separatorColor.cgColor
            box.layer?.backgroundColor = NSColor.unemphasizedSelectedContentBackgroundColor.cgColor
            box.translatesAutoresizingMaskIntoConstraints = false
            box.addSubview(promptLabel)
            NSLayoutConstraint.activate([
                box.widthAnchor.constraint(equalToConstant: width),
                promptLabel.leadingAnchor.constraint(equalTo: box.leadingAnchor, constant: 10),
                promptLabel.trailingAnchor.constraint(equalTo: box.trailingAnchor, constant: -10),
                promptLabel.topAnchor.constraint(equalTo: box.topAnchor, constant: 8),
                promptLabel.bottomAnchor.constraint(equalTo: box.bottomAnchor, constant: -8),
            ])
            root.addArrangedSubview(box)
        }

        let asksCodeEarly = serverPrompts.contains(where: WarmSignInPrompt.looksLikeCodePrompt)
        let asksDuoEarly = serverPrompts.contains(where: WarmSignInPrompt.looksLikeDuoMenu)
        if !serverPrompts.isEmpty {
            let readAs: String
            if asksDuoEarly {
                readAs = "Burrow read this as a Duo device prompt — approve on your phone, or send a push below."
            } else if asksCodeEarly {
                readAs = "Burrow read this as a verification-code request and will send whatever you enter in the code field."
            } else {
                readAs = "Burrow didn't recognize this as a code prompt — answer it in the field that fits (code or password)."
            }
            let detectLabel = NSTextField(wrappingLabelWithString: readAs)
            detectLabel.font = .systemFont(ofSize: 10.5)
            detectLabel.textColor = .secondaryLabelColor
            detectLabel.translatesAutoresizingMaskIntoConstraints = false
            detectLabel.widthAnchor.constraint(equalToConstant: width).isActive = true
            root.addArrangedSubview(detectLabel)
        }

        let codeField = NSTextField()
        codeField.placeholderString = "2FA code / passcode (if asked)"
        let passwordField = NSSecureTextField()
        passwordField.placeholderString = "Password (if asked)"
        for field in [codeField, passwordField] as [NSTextField] {
            field.translatesAutoresizingMaskIntoConstraints = false
            field.widthAnchor.constraint(equalToConstant: width).isActive = true
            field.heightAnchor.constraint(equalToConstant: 24).isActive = true
            root.addArrangedSubview(field)
        }
        self.codeField = codeField
        self.passwordField = passwordField

        if let availableCode, let linkedAccountName {
            let target = ClosureTarget { [weak codeField] in codeField?.stringValue = availableCode }
            let insertButton = NSButton(title: "Insert \(linkedAccountName) code", target: target, action: #selector(ClosureTarget.fire))
            insertButton.bezelStyle = .rounded
            insertButton.controlSize = .small
            insertButton.translatesAutoresizingMaskIntoConstraints = false
            root.addArrangedSubview(insertButton)
            buttonTargets.append(target)
        } else if let linkedAccountName {
            let hint = NSTextField(wrappingLabelWithString: "Leave the code blank to use your linked \(linkedAccountName) code automatically (Touch ID).")
            hint.font = .systemFont(ofSize: 10.5)
            hint.textColor = .secondaryLabelColor
            hint.translatesAutoresizingMaskIntoConstraints = false
            hint.widthAnchor.constraint(equalToConstant: width).isActive = true
            root.addArrangedSubview(hint)
        }

        // Buttons: Cancel · Send Duo Push · Warm (default).
        let buttonRow = NSStackView()
        buttonRow.orientation = .horizontal
        buttonRow.spacing = 8
        buttonRow.translatesAutoresizingMaskIntoConstraints = false
        buttonRow.widthAnchor.constraint(equalToConstant: width).isActive = true

        let cancelTarget = ClosureTarget { [weak self] in self?.resolve(nil) }
        let cancelButton = NSButton(title: "Cancel", target: cancelTarget, action: #selector(ClosureTarget.fire))
        cancelButton.bezelStyle = .rounded
        cancelButton.keyEquivalent = "\u{1b}" // Esc
        buttonTargets.append(cancelTarget)

        let duoTarget = ClosureTarget { [weak self] in
            let password = self?.passwordField?.stringValue.trimmingCharacters(in: .newlines) ?? ""
            self?.resolve(WarmSignInPrompt.Result(code: nil, password: password.isEmpty ? nil : password, sendDuoPush: true))
        }
        let duoButton = NSButton(title: "Send Duo Push", target: duoTarget, action: #selector(ClosureTarget.fire))
        duoButton.bezelStyle = .rounded
        buttonTargets.append(duoTarget)

        let warmTarget = ClosureTarget { [weak self] in
            guard let self else { return }
            let code = self.codeField?.stringValue.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            let password = self.passwordField?.stringValue.trimmingCharacters(in: .newlines) ?? ""
            self.resolve(WarmSignInPrompt.Result(
                code: code.isEmpty ? nil : code,
                password: password.isEmpty ? nil : password,
                sendDuoPush: false
            ))
        }
        let warmButton = NSButton(title: "Warm", target: warmTarget, action: #selector(ClosureTarget.fire))
        warmButton.bezelStyle = .rounded
        warmButton.keyEquivalent = "\r" // Return
        buttonTargets.append(warmTarget)

        buttonRow.addArrangedSubview(cancelButton)
        buttonRow.addArrangedSubview(NSView()) // spacer
        buttonRow.addArrangedSubview(duoButton)
        buttonRow.addArrangedSubview(warmButton)
        root.addArrangedSubview(buttonRow)

        root.layoutSubtreeIfNeeded()
        root.setFrameSize(root.fittingSize)
        return root
    }
}

enum FolderPrompt {
    /// Collects a new mounted-folder definition. Kept deliberately small: the
    /// host field takes an ~/.ssh/config alias (jump/user/port come from ssh
    /// config then), with explicit jump for bare hostnames.
    @MainActor
    static func request(knownHosts: [String]) -> FolderConfig? {
        let alert = NSAlert()
        alert.messageText = "New Mounted Folder"
        alert.informativeText = "Mounts a remote directory in the Finder over SSH (FUSE-T). Mounting is non-interactive — keep the host warm and mounts are instant with no prompts.\(knownHosts.isEmpty ? "" : "\n\nHosts in your ssh config: \(knownHosts.prefix(6).joined(separator: ", "))")"

        let width: CGFloat = 360
        let container = NSStackView(frame: NSRect(x: 0, y: 0, width: width, height: 116))
        container.orientation = .vertical
        container.alignment = .leading
        container.spacing = 6

        let nameField = NSTextField(frame: .zero)
        nameField.placeholderString = "Name (e.g. vista-projects)"
        let hostField = NSTextField(frame: .zero)
        hostField.placeholderString = "SSH host or alias (e.g. vista)"
        let remoteField = NSTextField(frame: .zero)
        remoteField.placeholderString = "Remote path (optional — home when empty)"
        let jumpField = NSTextField(frame: .zero)
        jumpField.placeholderString = "Jump host (optional, e.g. randi)"

        for field in [nameField, hostField, remoteField, jumpField] {
            field.translatesAutoresizingMaskIntoConstraints = false
            field.widthAnchor.constraint(equalToConstant: width).isActive = true
            container.addArrangedSubview(field)
        }
        alert.accessoryView = container
        alert.window.initialFirstResponder = nameField

        alert.addButton(withTitle: "Add Folder")
        alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else {
            return nil
        }
        let name = nameField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        let host = hostField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        let remote = remoteField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        let jump = jumpField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty, !host.isEmpty else {
            return nil
        }
        return FolderConfig(
            name: name,
            host: host,
            remotePath: remote,
            jumpHost: jump.isEmpty ? nil : jump
        )
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

    /// Collects a host's TOTP setup key so Burrow can enter 2FA codes for it
    /// automatically. Sensitive but shown plainly (matching the Authenticator) so
    /// the user can verify what they paste.
    @MainActor
    static func requestTwoFactorSecret(alias: String) -> String? {
        let alert = NSAlert()
        alert.messageText = "Enroll 2FA for \(alias)"
        alert.informativeText = "Paste this host's authenticator setup key — its otpauth:// link or the “can't scan” base32 secret.\n\nBurrow stores it in your macOS Keychain and asks for Touch ID / your Mac password before generating a code whenever it keeps \(alias) warm. This works only for TOTP-based 2FA — a Duo push or hardware token has no key to enroll."

        let field = NSTextField(frame: NSRect(x: 0, y: 0, width: 340, height: 24))
        field.placeholderString = "otpauth://… or base32 key"
        alert.accessoryView = field
        alert.window.initialFirstResponder = field

        alert.addButton(withTitle: "Enroll & Link")
        alert.addButton(withTitle: "Cancel")

        guard alert.runModal() == .alertFirstButtonReturn else {
            return nil
        }
        let secret = field.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        return secret.isEmpty ? nil : secret
    }

    struct EditResult {
        let hostName: String
        let user: String?
        let port: Int?
    }

    /// Edits an existing host's address / user / port. The alias is fixed (shown
    /// in the title, not editable — renaming is a separate concern); fields are
    /// pre-filled with the current values. Only these three directives change.
    @MainActor
    static func requestEdit(alias: String, hostName: String, user: String?, port: Int?) -> EditResult? {
        let alert = NSAlert()
        alert.messageText = "Edit \(alias)"
        alert.informativeText = "Updates HostName / User / Port for “\(alias)” in ~/.ssh/config. Burrow changes only those lines and leaves the rest of the stanza (ControlMaster, ProxyJump, comments, …) untouched."

        let width: CGFloat = 360
        let container = NSStackView(frame: NSRect(x: 0, y: 0, width: width, height: 88))
        container.orientation = .vertical
        container.alignment = .leading
        container.spacing = 6

        let hostField = NSTextField(frame: NSRect(x: 0, y: 0, width: width, height: 24))
        hostField.placeholderString = "Host address (e.g. gpu.lab.edu or 10.0.0.5)"
        hostField.stringValue = hostName
        let userField = NSTextField(frame: NSRect(x: 0, y: 0, width: width, height: 24))
        userField.placeholderString = "User (optional)"
        userField.stringValue = user ?? ""
        let portField = NSTextField(frame: NSRect(x: 0, y: 0, width: width, height: 24))
        portField.placeholderString = "Port (optional, default 22)"
        portField.stringValue = port.map(String.init) ?? ""

        for field in [hostField, userField, portField] {
            field.translatesAutoresizingMaskIntoConstraints = false
            field.widthAnchor.constraint(equalToConstant: width).isActive = true
            container.addArrangedSubview(field)
        }
        alert.accessoryView = container
        alert.window.initialFirstResponder = hostField

        alert.addButton(withTitle: "Save Changes")
        alert.addButton(withTitle: "Cancel")

        guard alert.runModal() == .alertFirstButtonReturn else {
            return nil
        }
        let host = hostField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        let editedUser = userField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        let editedPort = Int(portField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines))
        guard !host.isEmpty else {
            return nil
        }
        return EditResult(
            hostName: host,
            user: editedUser.isEmpty ? nil : editedUser,
            port: editedPort
        )
    }
}

enum AskPassSupport {
    static func environment(password: String) throws -> [String: String] {
        let scriptURL = try askPassScriptURL()
        cleanUpStaleLogs()
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
    /// (if any), 2FA / one-time-code prompts with `otpCode`, and a Duo device
    /// menu ("Passcode or option (1-3):") with `duoOption` (the push choice) when
    /// set. Used for the no-tty `ssh -fN` warm connection, where
    /// SSH_ASKPASS_REQUIRE=force routes keyboard-interactive prompts through the
    /// helper.
    static func warmEnvironment(password: String?, otpCode: String?, duoOption: String? = nil, promptLog: URL? = nil) throws -> [String: String] {
        let scriptURL = try promptAwareScriptURL()
        var env: [String: String] = [
            "SSH_ASKPASS": scriptURL.path,
            "SSH_ASKPASS_REQUIRE": "force",
            "DISPLAY": "burrow",
        ]
        if let password { env["BURROW_PASSWORD"] = password }
        if let otpCode { env["BURROW_OTP_CODE"] = otpCode }
        if let duoOption { env["BURROW_DUO_OPTION"] = duoOption }
        if let promptLog { env["BURROW_PROMPT_LOG"] = promptLog.path }
        return env
    }

    /// A private file the warm askpass appends each server prompt to, so the
    /// sign-in dialog can show what the host actually asked instead of making
    /// the user guess. The name carries the askpass prefix so the stale-log
    /// sweep covers any file a crashed attempt leaves behind.
    static func makePromptLog() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("burrow-askpass-prompts-\(UUID().uuidString).log")
    }

    /// The prompts recorded during one attempt, oldest first, de-duplicated.
    /// Consumes the log — call exactly once per attempt, success or failure.
    static func consumePrompts(at url: URL) -> [String] {
        defer { try? FileManager.default.removeItem(at: url) }
        guard let text = try? String(contentsOf: url, encoding: .utf8) else {
            return []
        }
        var seen = Set<String>()
        return text.split(whereSeparator: \.isNewline)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && seen.insert($0).inserted }
    }

    /// Each launch mints a fresh askpass log that nothing deletes afterwards;
    /// sweep old ones so they don't accumulate for the life of the temp dir.
    /// The mtime cutoff keeps logs a still-running session may yet write to.
    private static func cleanUpStaleLogs() {
        let fileManager = FileManager.default
        let directory = fileManager.temporaryDirectory
        guard let entries = try? fileManager.contentsOfDirectory(
            at: directory,
            includingPropertiesForKeys: [.contentModificationDateKey]
        ) else { return }

        let cutoff = Date().addingTimeInterval(-24 * 60 * 60)
        for url in entries
        where url.lastPathComponent.hasPrefix("burrow-askpass-") && url.pathExtension == "log" {
            let modified = (try? url.resourceValues(forKeys: [.contentModificationDateKey]))?
                .contentModificationDate ?? .distantPast
            if modified < cutoff {
                try? fileManager.removeItem(at: url)
            }
        }
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
        // $1 is the prompt text. A Duo device menu ("...option (1-3):") gets the
        // push option; code-ish prompts get the OTP; everything else gets the
        // password. Each branch falls back to the other value if one is empty.
        let contents = """
        #!/bin/sh
        # Record what the host asked (server text, not a secret) so the app
        # can show it in the sign-in dialog.
        if [ -n "$BURROW_PROMPT_LOG" ]; then
          ( umask 077; printf '%s\\n' "$1" >> "$BURROW_PROMPT_LOG" ) 2>/dev/null
        fi
        # Nothing to answer with? Abort rather than submit an empty response —
        # the attempt fails fast and harmlessly, but the prompt is captured.
        if [ -z "$BURROW_DUO_OPTION" ] && [ -z "$BURROW_OTP_CODE" ] && [ -z "$BURROW_PASSWORD" ]; then
          exit 1
        fi
        prompt=$(printf '%s' "$1" | tr 'A-Z' 'a-z')
        case "$prompt" in
          *option*|*duo*push*)
            if [ -n "$BURROW_DUO_OPTION" ]; then printf '%s\\n' "$BURROW_DUO_OPTION"
            elif [ -n "$BURROW_OTP_CODE" ]; then printf '%s\\n' "$BURROW_OTP_CODE"
            else printf '%s\\n' "$BURROW_PASSWORD"; fi
            ;;
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
