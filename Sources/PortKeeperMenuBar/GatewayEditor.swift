import PortKeeperCore
import SwiftUI

struct GatewayDraft: Identifiable {
    let id = UUID()
    let originalName: String?
    var name: String
    var vpnProtocol: String
    var server: String
    var user: String
    var authMode: String
    var samlGroup: String
    var socksPort: String
    var sshHostPatternsText: String
    var extraArgsText: String

    static let protocolChoices: [(id: String, label: String)] = [
        ("gp", "GlobalProtect"),
        ("anyconnect", "AnyConnect"),
        ("pulse", "Pulse"),
        ("fortinet", "Fortinet"),
    ]

    init(gateway: GatewayConfig, originalName: String?) {
        self.originalName = originalName
        self.name = gateway.name
        self.vpnProtocol = gateway.vpnProtocol
        self.server = gateway.server
        self.user = gateway.user ?? ""
        self.authMode = gateway.authMode
        self.samlGroup = gateway.samlGroup ?? ""
        self.socksPort = String(gateway.socksPort)
        self.sshHostPatternsText = gateway.sshHostPatterns.joined(separator: ", ")
        self.extraArgsText = gateway.extraArgs.joined(separator: "\n")
    }

    static func newGateway(from existing: [GatewayConfig]) -> GatewayDraft {
        let usedPorts = Set(existing.map(\.socksPort))
        var port = 11080
        while usedPorts.contains(port) {
            port += 1
        }
        let usedNames = Set(existing.map(\.name))
        var name = "vpn"
        var suffix = 2
        while usedNames.contains(name) {
            name = "vpn-\(suffix)"
            suffix += 1
        }
        return GatewayDraft(
            gateway: GatewayConfig(name: name, vpnProtocol: "gp", server: "", socksPort: port, authMode: "saml"),
            originalName: nil
        )
    }

    func toGatewayConfig() throws -> GatewayConfig {
        let trimmedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedServer = server
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: "https://", with: "")
            .trimmingCharacters(in: CharacterSet(charactersIn: "/"))

        guard !trimmedName.isEmpty else {
            throw DraftError("Gateway name is required.")
        }
        guard !trimmedServer.isEmpty else {
            throw DraftError("VPN server is required.")
        }
        guard let portValue = Int(socksPort), portValue > 0 else {
            throw DraftError("SOCKS port must be a valid integer.")
        }

        let patterns = sshHostPatternsText
            .split(whereSeparator: { $0 == "," || $0.isNewline })
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }

        let args = extraArgsText
            .split(whereSeparator: \.isWhitespace)
            .map(String.init)
            .filter { !$0.isEmpty }

        let trimmedUser = user.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedGroup = samlGroup.trimmingCharacters(in: .whitespacesAndNewlines)
        return GatewayConfig(
            name: trimmedName,
            vpnProtocol: vpnProtocol,
            server: trimmedServer,
            user: trimmedUser.isEmpty ? nil : trimmedUser,
            socksPort: portValue,
            authMode: authMode,
            samlGroup: trimmedGroup.isEmpty ? nil : trimmedGroup,
            sshHostPatterns: patterns,
            extraArgs: args
        )
    }
}

struct GatewayEditorSheet: View {
    @Binding var draft: GatewayDraft
    let onCancel: () -> Void
    let onSave: () -> Void
    let onDelete: () -> Void
    @State private var detectedVPNs: [DetectedVPN] = []

    // SSO autodetection: a credential-free probe of the server's login endpoint
    // (SAML redirect / GP prelogin). A definitive "SSO" auto-selects SAML on a
    // new gateway and warns when password mode is picked anyway.
    @State private var ssoVerdict: VPNSSODetector.Verdict?
    @State private var ssoProbeTask: Task<Void, Never>?
    /// True once the user chose a sign-in mode themselves (or is editing an
    /// existing gateway) — autodetection then advises but never overrides.
    @State private var authModePinnedByUser = false

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            VStack(alignment: .leading, spacing: 2) {
                Text(draft.originalName == nil ? "New VPN Gateway" : "Edit VPN Gateway")
                    .font(.system(size: 16, weight: .bold))
                Text("Runs openconnect + ocproxy: the VPN becomes a local SOCKS port. No root, no routing changes.")
                    .font(.system(size: 10.5))
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            }

            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    connectionSection
                    sshSection
                }
                .padding(.vertical, 2)
            }

            Divider()

            HStack {
                if draft.originalName != nil {
                    Button("Delete", role: .destructive, action: onDelete)
                }
                Spacer()
                Button("Cancel", action: onCancel)
                Button("Save", action: onSave)
                    .keyboardShortcut(.defaultAction)
            }
            .buttonStyle(.bordered)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .onAppear {
            detectedVPNs = VPNClientConfigScanner.detect()
            authModePinnedByUser = draft.originalName != nil
            scheduleSSOProbe(debounce: false)
        }
        .onChange(of: draft.server) { _ in scheduleSSOProbe(debounce: true) }
        .onChange(of: draft.vpnProtocol) { _ in scheduleSSOProbe(debounce: true) }
        .onChange(of: draft.samlGroup) { _ in scheduleSSOProbe(debounce: true) }
        .onDisappear { ssoProbeTask?.cancel() }
    }

    /// Probes the (debounced) current server for browser SSO. On a definitive
    /// yes: auto-select SAML unless the user pinned a mode; the caption under
    /// the Sign-in picker explains either way.
    private func scheduleSSOProbe(debounce: Bool) {
        ssoProbeTask?.cancel()
        ssoVerdict = nil
        let server = draft.server.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !server.isEmpty else { return }
        let vpnProtocol = draft.vpnProtocol
        let group = draft.samlGroup
        ssoProbeTask = Task {
            if debounce {
                try? await Task.sleep(for: .milliseconds(700))
            }
            guard !Task.isCancelled else { return }
            let verdict = await VPNSSODetector.probe(server: server, vpnProtocol: vpnProtocol, samlGroup: group)
            guard !Task.isCancelled else { return }
            await MainActor.run {
                ssoVerdict = verdict
                guard case .sso(let suggestedGroup) = verdict else { return }
                if !authModePinnedByUser && draft.authMode != "saml" {
                    withAnimation { draft.authMode = "saml" }
                }
                // Fill the discovered tunnel group when the user hasn't set one —
                // the piece nobody knows by heart (e.g. "cvpn-conn-profile").
                if let suggestedGroup,
                   draft.samlGroup.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    draft.samlGroup = suggestedGroup
                }
            }
        }
    }

    private var detectedSSO: Bool {
        if case .sso = ssoVerdict { return true }
        return false
    }

    private var connectionSection: some View {
        GatewayEditorSection(
            title: "VPN Connection",
            subtitle: "The server address from your official VPN client."
        ) {
            Grid(alignment: .leading, horizontalSpacing: 10, verticalSpacing: 8) {
                if !detectedVPNs.isEmpty && draft.originalName == nil {
                    GridRow {
                        label("Detected")
                        HStack(spacing: 8) {
                            Menu("Use a VPN from your installed clients…") {
                                ForEach(detectedVPNs) { detected in
                                    Button("\(detected.label) — \(detected.server)") {
                                        apply(detected)
                                    }
                                }
                            }
                            .controlSize(.small)
                            .frame(maxWidth: 300)
                            Spacer()
                        }
                    }
                }
                GridRow {
                    label("Name")
                    TextField("campus", text: $draft.name)
                        .textFieldStyle(.roundedBorder)
                }
                GridRow {
                    label("Type")
                    Picker("Type", selection: $draft.vpnProtocol) {
                        ForEach(GatewayDraft.protocolChoices, id: \.id) { choice in
                            Text(choice.label).tag(choice.id)
                        }
                    }
                    .labelsHidden()
                    .pickerStyle(.segmented)
                    .frame(maxWidth: 320)
                }
                GridRow {
                    label("Server")
                    TextField("vpn.example.edu", text: $draft.server)
                        .textFieldStyle(.roundedBorder)
                }
                GridRow {
                    label("Sign-in")
                    Picker("Sign-in", selection: Binding(
                        get: { draft.authMode },
                        set: { draft.authMode = $0; authModePinnedByUser = true }
                    )) {
                        Text("SAML (browser)").tag("saml")
                        Text("Password").tag("password")
                    }
                    .labelsHidden()
                    .pickerStyle(.segmented)
                    .frame(maxWidth: 240)
                }
                if detectedSSO {
                    GridRow {
                        Color.clear.frame(width: 1, height: 1)
                        if draft.authMode == "saml" {
                            Label("This server signs in with SSO (browser) — SAML is right.", systemImage: "checkmark.seal.fill")
                                .font(.system(size: 10))
                                .foregroundStyle(.green)
                        } else {
                            HStack(spacing: 8) {
                                Label("This server signs in with SSO (browser) — password mode can’t complete it.", systemImage: "exclamationmark.triangle.fill")
                                    .font(.system(size: 10))
                                    .foregroundStyle(.orange)
                                Button("Use SAML") {
                                    draft.authMode = "saml"
                                    authModePinnedByUser = true
                                }
                                .controlSize(.small)
                            }
                        }
                    }
                }
                if draft.authMode == "saml" && draft.vpnProtocol == "anyconnect" {
                    GridRow {
                        label("SAML Group")
                        HStack(spacing: 8) {
                            TextField("optional — e.g. cvpn-conn-profile", text: $draft.samlGroup)
                                .textFieldStyle(.roundedBorder)
                                .frame(width: 180)
                            Text("tunnel group; empty shows the logon page's group picker")
                                .font(.system(size: 10))
                                .foregroundStyle(.secondary)
                            Spacer()
                        }
                    }
                }
                GridRow {
                    label("User")
                    HStack(spacing: 8) {
                        TextField(draft.authMode == "saml" ? "optional — from SAML" : "alice", text: $draft.user)
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 180)
                        if draft.authMode == "saml" {
                            Text("fallback if SSO doesn't return one")
                                .font(.system(size: 10))
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                    }
                }
                GridRow {
                    label("SOCKS Port")
                    HStack(spacing: 8) {
                        TextField("11080", text: $draft.socksPort)
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 92)
                        Text("local port apps and tunnels connect through")
                            .font(.system(size: 10))
                            .foregroundStyle(.secondary)
                        Spacer()
                    }
                }
            }
        }
    }

    private var sshSection: some View {
        GatewayEditorSection(
            title: "SSH + Advanced",
            subtitle: "Host patterns make plain `ssh` route through this gateway via the generated include file."
        ) {
            Grid(alignment: .leading, horizontalSpacing: 10, verticalSpacing: 8) {
                GridRow {
                    label("SSH Hosts")
                    TextField("*.example.edu, 172.18.*", text: $draft.sshHostPatternsText)
                        .textFieldStyle(.roundedBorder)
                }
            }

            VStack(alignment: .leading, spacing: 5) {
                Text("Extra openconnect arguments")
                    .font(.system(size: 10.5, weight: .semibold))
                    .foregroundStyle(.secondary)
                TextEditor(text: $draft.extraArgsText)
                    .font(.system(size: 11, design: .monospaced))
                    .frame(minHeight: 56)
                    .overlay(
                        RoundedRectangle(cornerRadius: 8)
                            .stroke(Color.secondary.opacity(0.16))
                    )
            }
        }
    }

    private func apply(_ detected: DetectedVPN) {
        draft.server = detected.server
        draft.vpnProtocol = detected.vpnProtocol
        if draft.name.isEmpty || draft.name == "vpn" || draft.name.hasPrefix("vpn-") {
            draft.name = detected.server.split(separator: ".").first.map(String.init) ?? detected.server
        }
    }

    private func label(_ text: String) -> some View {
        Text(text)
            .font(.system(size: 10.5, weight: .semibold))
            .foregroundStyle(.secondary)
            .frame(width: 72, alignment: .trailing)
    }
}

private struct GatewayEditorSection<Content: View>: View {
    let title: String
    let subtitle: String
    @ViewBuilder let content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.system(size: 12.5, weight: .bold))
                Text(subtitle)
                    .font(.system(size: 10.5))
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            }
            content
        }
        .padding(10)
        .background(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .fill(Color(nsColor: .controlBackgroundColor).opacity(0.62))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .stroke(Color.primary.opacity(0.06), lineWidth: 1)
        )
    }
}
