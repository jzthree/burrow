import AppKit
import Darwin
import PortKeeperCore
import SwiftUI

/// Hosts the tunnel editor in a real window so a half-filled form survives
/// clicks outside the menu-bar popover.
@MainActor
final class EditorWindowController: NSObject, NSWindowDelegate {
    private weak var viewModel: MenuBarViewModel?
    private var window: NSWindow?
    private var isSyncing = false

    init(viewModel: MenuBarViewModel) {
        self.viewModel = viewModel
    }

    func present(title: String) {
        if window == nil {
            window = makeWindow()
        }
        window?.title = title
        MenuBarPopover.dismiss()
        window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    func dismiss() {
        guard !isSyncing, let window, window.isVisible else {
            return
        }
        isSyncing = true
        window.close()
        isSyncing = false
    }

    func windowWillClose(_ notification: Notification) {
        guard !isSyncing else {
            return
        }
        isSyncing = true
        viewModel?.editorDraft = nil
        viewModel?.gatewayDraft = nil
        viewModel?.profileDraft = nil
        isSyncing = false
    }

    private func makeWindow() -> NSWindow? {
        guard let viewModel else {
            return nil
        }

        let hosting = NSHostingController(rootView: EditorWindowContent(viewModel: viewModel))
        let window = NSWindow(contentViewController: hosting)
        window.styleMask = [.titled, .closable, .miniaturizable]
        window.isReleasedWhenClosed = false
        window.level = .floating
        window.delegate = self
        window.center()
        return window
    }
}

private struct EditorWindowContent: View {
    @ObservedObject var viewModel: MenuBarViewModel

    var body: some View {
        Group {
            if let profileDraft = viewModel.profileDraft {
                ProfileEditorSheet(
                    draft: profileBinding(for: profileDraft),
                    tunnelNames: viewModel.tunnels.map(\.id),
                    gatewayNames: viewModel.gateways.map(\.id),
                    onCancel: { viewModel.closeProfileEditor() },
                    onSave: { viewModel.saveProfileEditor() },
                    onDelete: { viewModel.deleteProfileEditorTarget() }
                )
                .padding(14)
            } else if let gatewayDraft = viewModel.gatewayDraft {
                GatewayEditorSheet(
                    draft: gatewayBinding(for: gatewayDraft),
                    onCancel: { viewModel.closeGatewayEditor() },
                    onSave: { viewModel.saveGatewayEditor() },
                    onDelete: { viewModel.deleteGatewayEditorTarget() }
                )
                .padding(14)
            } else if let draft = viewModel.editorDraft {
                TunnelEditorSheet(
                    draft: binding(for: draft),
                    suggestions: TunnelEditorSuggestions(
                        tunnels: viewModel.tunnels.map(\.tunnel),
                        sshHosts: viewModel.sshConfigHosts,
                        gatewayNames: viewModel.gateways.map(\.id)
                    ),
                    conflictChecker: PortConflictChecker(
                        savedTunnels: viewModel.tunnels.map(\.tunnel),
                        excludedTunnelName: draft.originalName,
                        runningTunnelNames: Set(viewModel.tunnels.filter(\.isRunning).map(\.id))
                    ),
                    onCancel: { viewModel.closeEditor() },
                    onSave: { viewModel.saveEditor() },
                    onDelete: { viewModel.deleteEditorTunnel() }
                )
                .padding(14)
            } else {
                Color.clear
            }
        }
        .frame(width: 500, height: 660)
    }

    private func binding(for draft: TunnelDraft) -> Binding<TunnelDraft> {
        Binding(
            get: { viewModel.editorDraft ?? draft },
            set: { viewModel.editorDraft = $0 }
        )
    }

    private func gatewayBinding(for draft: GatewayDraft) -> Binding<GatewayDraft> {
        Binding(
            get: { viewModel.gatewayDraft ?? draft },
            set: { viewModel.gatewayDraft = $0 }
        )
    }

    private func profileBinding(for draft: ProfileDraft) -> Binding<ProfileDraft> {
        Binding(
            get: { viewModel.profileDraft ?? draft },
            set: { viewModel.profileDraft = $0 }
        )
    }
}

/// Static + live checks for local listen-port collisions, shown inline in the editor.
struct PortConflictChecker: Sendable {
    let savedTunnels: [TunnelConfig]
    let excludedTunnelName: String?
    let runningTunnelNames: Set<String>

    func savedTunnelConflict(port: Int) -> String? {
        for tunnel in savedTunnels where tunnel.name != excludedTunnelName {
            for forward in tunnel.forwards where forward.kind != .remote && forward.listenPort == port {
                return "Port \(port) is already used by tunnel “\(tunnel.name)”."
            }
        }
        return nil
    }

    /// True when the port belongs to the tunnel being edited and that tunnel is
    /// currently running, so its own ssh process legitimately holds the listener.
    func portHeldByEditedTunnel(_ port: Int) -> Bool {
        guard let excludedTunnelName, runningTunnelNames.contains(excludedTunnelName),
              let tunnel = savedTunnels.first(where: { $0.name == excludedTunnelName }) else {
            return false
        }
        return tunnel.forwards.contains { $0.kind != .remote && $0.listenPort == port }
    }

    func isPortInUseLocally(_ port: Int) -> Bool {
        let socketFD = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        guard socketFD >= 0 else {
            return false
        }
        defer { close(socketFD) }

        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = in_port_t(UInt16(clamping: port)).bigEndian
        address.sin_addr.s_addr = inet_addr("127.0.0.1")

        let result = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
                connect(socketFD, sockaddrPointer, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        return result == 0
    }
}
