import PortKeeperCore
import SwiftUI

struct SSHConfigImportCandidate: Identifiable {
    let host: SSHConfigHost
    var include: Bool
    var tunnelName: String

    var id: String { host.alias }

    var endpointSummary: String {
        let user = host.user.map { "\($0)@" } ?? ""
        let port = host.port.map { ":\($0)" } ?? ""
        return "\(user)\(host.effectiveHost)\(port)"
    }

    var forwardSummary: String {
        host.forwards.map { forward in
            switch forward.kind {
            case .local:
                return "\(forward.listenPort) -> \(forward.destinationHost ?? "?"):\(forward.destinationPort.map(String.init) ?? "?")"
            case .remote:
                return "\(forward.destinationHost ?? "?"):\(forward.destinationPort.map(String.init) ?? "?") <- \(forward.listenPort)"
            case .dynamic:
                return "SOCKS \(forward.listenPort)"
            }
        }
        .joined(separator: "  •  ")
    }

    func toTunnelConfig() -> TunnelConfig {
        TunnelConfig(
            name: tunnelName,
            host: host.effectiveHost,
            user: host.user,
            sshPort: host.port ?? 22,
            identityFile: host.identityFile,
            jumpHost: host.proxyJump,
            forwards: host.forwards,
            enabled: false
        )
    }
}

struct SSHConfigImportView: View {
    @Binding var candidates: [SSHConfigImportCandidate]
    let onCancel: () -> Void
    let onImport: () -> Void

    private var selectedCount: Int {
        candidates.filter(\.include).count
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            VStack(alignment: .leading, spacing: 2) {
                Text("Import from SSH Config")
                    .font(.system(size: 16, weight: .bold))
                Text("Hosts in ~/.ssh/config that define port forwards. Imported tunnels start with auto-connect off.")
                    .font(.system(size: 10.5))
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            }

            ScrollView {
                VStack(alignment: .leading, spacing: 6) {
                    ForEach($candidates) { $candidate in
                        HStack(alignment: .top, spacing: 9) {
                            Toggle("", isOn: $candidate.include)
                                .toggleStyle(.checkbox)
                                .labelsHidden()
                                .padding(.top, 1)
                            VStack(alignment: .leading, spacing: 2) {
                                HStack(spacing: 6) {
                                    Text(candidate.tunnelName)
                                        .font(.system(size: 12.5, weight: .semibold))
                                        .lineLimit(1)
                                    if candidate.tunnelName != candidate.host.alias {
                                        Text("from \(candidate.host.alias)")
                                            .font(.system(size: 10))
                                            .foregroundStyle(.secondary)
                                    }
                                }
                                Text(candidate.endpointSummary)
                                    .font(.system(size: 10.5, design: .monospaced))
                                    .foregroundStyle(.secondary)
                                    .lineLimit(1)
                                    .truncationMode(.middle)
                                Text(candidate.forwardSummary)
                                    .font(.system(size: 10.5, design: .monospaced))
                                    .foregroundStyle(.secondary.opacity(0.85))
                                    .lineLimit(2)
                            }
                            Spacer(minLength: 0)
                        }
                        .padding(9)
                        .background(
                            RoundedRectangle(cornerRadius: 10, style: .continuous)
                                .fill(Color(nsColor: .controlBackgroundColor).opacity(candidate.include ? 0.62 : 0.30))
                        )
                    }
                }
                .padding(.vertical, 2)
            }

            Divider()

            HStack {
                Spacer()
                Button("Cancel", action: onCancel)
                Button("Import \(selectedCount) Tunnel\(selectedCount == 1 ? "" : "s")", action: onImport)
                    .keyboardShortcut(.defaultAction)
                    .disabled(selectedCount == 0)
            }
            .buttonStyle(.bordered)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }
}
