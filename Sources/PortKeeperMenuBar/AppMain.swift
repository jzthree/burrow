import AppKit
import Combine
import PortKeeperCore
import SwiftUI

@main
struct BurrowApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    private let viewModel = MenuBarViewModel()

    var body: some Scene {
        MenuBarExtra {
            MenuBarContent(viewModel: viewModel)
        } label: {
            MenuBarLabel(viewModel: viewModel)
        }
        .menuBarExtraStyle(.window)
    }
}

private struct MenuBarLabel: View {
    @ObservedObject var viewModel: MenuBarViewModel

    var body: some View {
        Label(viewModel.menuBarTitle, systemImage: viewModel.menuBarSymbol)
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
        NotificationCenter.default.post(name: .portKeeperDidFinishLaunching, object: nil)
    }
}

@MainActor
final class MenuBarViewModel: ObservableObject {
    enum ConnectionState: Equatable {
        case disconnected
        case connecting
        case connected
        case failed
    }

    struct TunnelState: Identifiable {
        let id: String
        let tunnel: TunnelConfig
        var isConfiguredEnabled: Bool
        var isRunning: Bool
        var connectionState: ConnectionState
        var lastMessage: String
        var recentLogs: [String]
    }

    let store = ConfigStore()
    let passwordStore = PasswordStore()

    @Published private(set) var tunnels: [TunnelState] = []
    @Published var globalMessage = ""
    @Published var editorDraft: TunnelDraft?

    private var tasks: [String: Task<Void, Never>] = [:]
    private var hasStartedAutoConnect = false
    private var pendingCredentialSaves: [String: PendingCredentialSave] = [:]
    private var activeCredentialSources: [String: CredentialSource] = [:]
    private var sawAuthenticationFailure: Set<String> = []
    private var sessionPasswords: [TunnelCredentialKey: String] = [:]
    private var sessionPasswordsByHostUser: [HostUserKey: String] = [:]
    private var savedCredentialKeysThisSession: Set<TunnelCredentialKey> = []
    private var invalidCredentialKeys: Set<TunnelCredentialKey> = []
    private var authRePromptCounts: [String: Int] = [:]

    init() {
        loadConfig()
        Task { @MainActor [weak self] in
            try? await Task.sleep(for: .milliseconds(250))
            self?.startEnabledTunnelsIfNeeded()
        }
        NotificationCenter.default.addObserver(
            forName: .portKeeperDidFinishLaunching,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor [weak self] in
                self?.startEnabledTunnelsIfNeeded()
            }
        }
        NotificationCenter.default.addObserver(
            forName: NSApplication.willTerminateNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor [weak self] in
                self?.stopAll()
            }
        }
    }

    deinit {
        for task in tasks.values {
            task.cancel()
        }
    }

    var menuBarTitle: String {
        let runningCount = tunnels.filter(\.isRunning).count
        return runningCount > 0 ? "Burrow \(runningCount)" : "Burrow"
    }

    var menuBarSymbol: String {
        tunnels.contains(where: \.isRunning)
            ? "point.3.filled.connected.trianglepath.dotted"
            : "point.3.connected.trianglepath.dotted"
    }

    func loadConfig() {
        do {
            let config = try store.load()
            let running = Set(tasks.keys)
            let existingStatesByName = Dictionary(uniqueKeysWithValues: tunnels.map { ($0.id, $0) })
            tunnels = config.tunnels.map { tunnel in
                let existingState = existingStatesByName[tunnel.name]
                let isRunning = running.contains(tunnel.name)
                return TunnelState(
                    id: tunnel.name,
                    tunnel: tunnel,
                    isConfiguredEnabled: tunnel.enabled,
                    isRunning: isRunning,
                    connectionState: connectionStateAfterReload(existingState: existingState, isRunning: isRunning),
                    lastMessage: lastMessageAfterReload(existingState: existingState, tunnel: tunnel, isRunning: isRunning),
                    recentLogs: existingState?.recentLogs ?? []
                )
            }

            if tunnels.isEmpty {
                globalMessage = "No tunnels configured yet."
            } else {
                let runningCount = tunnels.filter(\.isRunning).count
                globalMessage = "Loaded \(tunnels.count) tunnel(s), \(runningCount) running."
            }
        } catch {
            tunnels = []
            globalMessage = "Failed to load config: \(error.localizedDescription)"
        }
    }

    private func connectionStateAfterReload(existingState: TunnelState?, isRunning: Bool) -> ConnectionState {
        if isRunning {
            return existingState?.connectionState ?? .connecting
        }

        if existingState?.connectionState == .failed {
            return .failed
        }

        return .disconnected
    }

    private func lastMessageAfterReload(existingState: TunnelState?, tunnel: TunnelConfig, isRunning: Bool) -> String {
        if isRunning {
            return existingState?.lastMessage ?? "Connecting"
        }

        if existingState?.connectionState == .failed, let lastMessage = existingState?.lastMessage {
            return lastMessage
        }

        return tunnel.enabled ? "Auto-connect enabled" : "Auto-connect disabled"
    }

    func reloadConfig() {
        stopMissingTunnels()
        loadConfig()
    }

    func startEnabledTunnels() {
        for tunnel in tunnels where tunnel.isConfiguredEnabled {
            startTunnel(named: tunnel.id, allowPasswordPrompt: false)
        }
    }

    func startEnabledTunnelsIfNeeded() {
        guard !hasStartedAutoConnect else {
            return
        }
        hasStartedAutoConnect = true
        startEnabledTunnels()
    }

    func startAll() {
        for tunnel in tunnels {
            startTunnel(named: tunnel.id)
        }
    }

    func stopAll() {
        for id in Array(tasks.keys) {
            stopTunnel(named: id)
        }
    }

    func restartTunnel(named name: String) {
        stopTunnel(named: name)
        startTunnel(named: name)
    }

    func startTunnel(named name: String, allowPasswordPrompt: Bool = true) {
        guard tasks[name] == nil else {
            updateState(for: name, isRunning: true, message: "Already running")
            return
        }
        guard let tunnel = tunnels.first(where: { $0.id == name })?.tunnel else {
            globalMessage = "Tunnel '\(name)' not found."
            return
        }

        let launchTunnel: TunnelConfig
        do {
            launchTunnel = try preparedTunnelForLaunch(tunnel)
        } catch {
            updateState(for: name, isRunning: false, state: .failed, message: "SSH option setup failed: \(error.localizedDescription)")
            globalMessage = "Failed to prepare SSH options for \(name)."
            return
        }

        let preparation: ConnectionPreparation
        do {
            preparation = try connectionPreparation(for: launchTunnel, allowPasswordPrompt: allowPasswordPrompt)
        } catch {
            updateState(for: name, isRunning: false, state: .failed, message: "Password setup failed: \(error.localizedDescription)")
            globalMessage = "Failed to prepare credentials for \(name)."
            return
        }

        if let pendingSave = preparation.pendingSave {
            pendingCredentialSaves[name] = pendingSave
        } else {
            pendingCredentialSaves[name] = nil
        }
        activeCredentialSources[name] = preparation.credentialSource
        sawAuthenticationFailure.remove(name)

        updateState(for: name, isRunning: true, state: .connecting, message: "Connecting")
        let bridge = TunnelEventBridge(owner: self, tunnelName: name)
        let task = Task.detached(priority: .userInitiated) {
            let supervisor = TunnelSupervisor(
                tunnel: launchTunnel,
                logger: { message in
                    bridge.log(message)
                },
                eventHandler: { event in
                    bridge.handle(event)
                },
                environment: preparation.environment
            )
            await supervisor.run()
            bridge.finish()
        }
        tasks[name] = task
        globalMessage = "Started \(name)."
    }

    func stopTunnel(named name: String) {
        let task = tasks[name]
        if task == nil,
           let tunnel = tunnels.first(where: { $0.id == name })?.tunnel,
           let preparedTunnel = try? preparedTunnelForLaunch(tunnel) {
            try? PortKeeperRuntimeRegistry.reclaimOwnedProcess(for: preparedTunnel)
        }

        guard let task else {
            updateState(for: name, isRunning: false, state: .disconnected, message: "Not running")
            return
        }

        task.cancel()
        tasks[name] = nil
        pendingCredentialSaves[name] = nil
        activeCredentialSources[name] = nil
        sawAuthenticationFailure.remove(name)
        authRePromptCounts[name] = 0
        updateState(for: name, isRunning: false, state: .disconnected, message: "Stopping")
        globalMessage = "Stopped \(name)."
    }

    func openConfig() {
        do {
            let url = try store.ensureExists()
            NSWorkspace.shared.open(url)
        } catch {
            globalMessage = "Failed to open config: \(error.localizedDescription)"
        }
    }

    func revealConfigFolder() {
        do {
            let url = try store.ensureExists()
            NSWorkspace.shared.activateFileViewerSelecting([url])
        } catch {
            globalMessage = "Failed to reveal config: \(error.localizedDescription)"
        }
    }

    func openEditor(for name: String) {
        guard let tunnel = tunnels.first(where: { $0.id == name })?.tunnel else {
            globalMessage = "Tunnel '\(name)' not found."
            return
        }
        editorDraft = TunnelDraft(tunnel: tunnel, originalName: tunnel.name)
    }

    func duplicateTunnel(named name: String) {
        guard let tunnel = tunnels.first(where: { $0.id == name })?.tunnel else {
            globalMessage = "Tunnel '\(name)' not found."
            return
        }

        var draft = TunnelDraft(tunnel: tunnel, originalName: nil)
        draft.name = uniqueDuplicateName(for: tunnel.name)
        editorDraft = draft
        globalMessage = "Duplicating \(name)."
    }

    func deleteTunnel(named name: String) {
        do {
            if tasks[name] != nil {
                stopTunnel(named: name)
            }
            _ = try store.remove(name: name)
            loadConfig()
            globalMessage = "Deleted \(name)."
            if editorDraft?.originalName == name {
                editorDraft = nil
            }
        } catch {
            globalMessage = "Delete failed: \(error.localizedDescription)"
        }
    }

    func setAutoConnect(named name: String, enabled: Bool) {
        do {
            var config = try store.load()
            guard let index = config.tunnels.firstIndex(where: { $0.name == name }) else {
                globalMessage = "Tunnel '\(name)' not found."
                return
            }
            config.tunnels[index].enabled = enabled
            try store.save(config)
            loadConfig()
            globalMessage = enabled ? "Enabled auto-connect for \(name)." : "Disabled auto-connect for \(name)."
        } catch {
            globalMessage = "Failed to update auto-connect: \(error.localizedDescription)"
        }
    }

    func createTunnel() {
        editorDraft = TunnelDraft.newTunnel(from: tunnels.map(\.tunnel))
    }

    func closeEditor() {
        editorDraft = nil
    }

    func saveEditor() {
        guard let draft = editorDraft else {
            return
        }

        do {
            let tunnel = try draft.toTunnelConfig()
            let originalName = draft.originalName
            let wasRunning = originalName.map { tasks[$0] != nil } ?? false
            var pendingOldTask: Task<Void, Never>?

            if let originalName, originalName != tunnel.name {
                pendingOldTask = tasks[originalName]
                if tasks[originalName] != nil {
                    stopTunnel(named: originalName)
                }
            }

            try store.upsert(tunnel, replacing: originalName)
            loadConfig()

            if wasRunning {
                if let pendingOldTask {
                    let newName = tunnel.name
                    updateState(for: newName, isRunning: false, state: .connecting, message: "Waiting for previous session to close")
                    Task { @MainActor [weak self] in
                        _ = await pendingOldTask.value
                        self?.startTunnel(named: newName)
                    }
                } else {
                    startTunnel(named: tunnel.name)
                }
            }

            globalMessage = "Saved \(tunnel.name)."
            editorDraft = nil
        } catch {
            globalMessage = "Save failed: \(error.localizedDescription)"
        }
    }

    func deleteEditorTunnel() {
        guard let draft = editorDraft, let originalName = draft.originalName else {
            return
        }

        do {
            if tasks[originalName] != nil {
                stopTunnel(named: originalName)
            }
            _ = try store.remove(name: originalName)
            loadConfig()
            globalMessage = "Deleted \(originalName)."
            editorDraft = nil
        } catch {
            globalMessage = "Delete failed: \(error.localizedDescription)"
        }
    }

    func quit() {
        stopAll()
        NSApp.terminate(nil)
    }

    private func connectionPreparation(for tunnel: TunnelConfig, allowPasswordPrompt: Bool) throws -> ConnectionPreparation {
        guard let credentialKey = TunnelCredentialKey(tunnel: tunnel) else {
            return ConnectionPreparation(environment: [:], pendingSave: nil, credentialSource: .none)
        }

        let hostUserKey = credentialKey.hostUserKey
        let isRetry = invalidCredentialKeys.contains(credentialKey)

        if !isRetry {
            if let sessionPassword = sessionPasswords[credentialKey], !sessionPassword.isEmpty {
                let pendingSave: PendingCredentialSave? = savedCredentialKeysThisSession.contains(credentialKey)
                    ? nil
                    : PendingCredentialSave(key: credentialKey, password: sessionPassword)
                return ConnectionPreparation(
                    environment: try AskPassSupport.environment(password: sessionPassword),
                    pendingSave: pendingSave,
                    credentialSource: .prompted(credentialKey)
                )
            }

            if let password = try passwordStore.password(for: credentialKey), !password.isEmpty {
                sessionPasswords[credentialKey] = password
                sessionPasswordsByHostUser[hostUserKey] = password
                return ConnectionPreparation(
                    environment: try AskPassSupport.environment(password: password),
                    pendingSave: nil,
                    credentialSource: .keychain(credentialKey)
                )
            }

            if let sharedPassword = sessionPasswordsByHostUser[hostUserKey], !sharedPassword.isEmpty {
                sessionPasswords[credentialKey] = sharedPassword
                return ConnectionPreparation(
                    environment: try AskPassSupport.environment(password: sharedPassword),
                    pendingSave: PendingCredentialSave(key: credentialKey, password: sharedPassword),
                    credentialSource: .prompted(credentialKey)
                )
            }
        }

        guard allowPasswordPrompt else {
            throw ConnectionPreparationError.missingSavedPassword(credentialKey.account)
        }

        guard let password = PasswordPrompt.requestPassword(
            for: credentialKey,
            tunnelName: tunnel.name,
            retry: isRetry
        ) else {
            throw ConnectionPreparationError.cancelledPasswordPrompt
        }

        sessionPasswords[credentialKey] = password
        sessionPasswordsByHostUser[hostUserKey] = password

        return ConnectionPreparation(
            environment: try AskPassSupport.environment(password: password),
            pendingSave: PendingCredentialSave(key: credentialKey, password: password),
            credentialSource: .prompted(credentialKey)
        )
    }

    private func preparedTunnelForLaunch(_ tunnel: TunnelConfig) throws -> TunnelConfig {
        try TunnelLaunchPreparer.prepare(tunnel)
    }

    private func stopMissingTunnels() {
        let configuredNames = Set((try? store.load().tunnels.map(\.name)) ?? [])
        for name in tasks.keys where !configuredNames.contains(name) {
            stopTunnel(named: name)
        }
    }

    fileprivate func updateState(for name: String, isRunning: Bool, state: ConnectionState? = nil, message: String) {
        guard let index = tunnels.firstIndex(where: { $0.id == name }) else {
            return
        }
        tunnels[index].isRunning = isRunning
        if let state {
            tunnels[index].connectionState = state
        }
        tunnels[index].lastMessage = message
    }

    fileprivate func appendLog(for name: String, message: String) {
        guard let index = tunnels.firstIndex(where: { $0.id == name }) else {
            return
        }
        let trimmed = message.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return
        }
        tunnels[index].recentLogs.append(trimmed)
        if tunnels[index].recentLogs.count > 20 {
            tunnels[index].recentLogs.removeFirst(tunnels[index].recentLogs.count - 20)
        }
    }

    fileprivate func finishTunnel(named name: String) {
        tasks[name] = nil
        pendingCredentialSaves[name] = nil
        let shouldPromptAgain = sawAuthenticationFailure.contains(name) && shouldAutoPromptAgain(for: name)
        if sawAuthenticationFailure.contains(name) {
            handleAuthenticationFailure(for: name)
        }
        activeCredentialSources[name] = nil
        sawAuthenticationFailure.remove(name)
        let state: ConnectionState = tunnels.first(where: { $0.id == name })?.connectionState == .failed ? .failed : .disconnected
        updateState(for: name, isRunning: false, state: state, message: state == .failed ? "Connect failed" : "Stopped")
        if shouldPromptAgain {
            authRePromptCounts[name, default: 0] += 1
            globalMessage = "Credentials for \(name) were rejected. Prompting to re-enter password."
            Task { @MainActor [weak self] in
                self?.startTunnel(named: name)
            }
        }
    }

    fileprivate func persistPasswordIfNeeded(for name: String) {
        guard let pendingSave = pendingCredentialSaves[name] else {
            return
        }

        if savedCredentialKeysThisSession.contains(pendingSave.key) {
            pendingCredentialSaves[name] = nil
            return
        }

        do {
            try passwordStore.save(password: pendingSave.password, for: pendingSave.key)
            pendingCredentialSaves[name] = nil
            savedCredentialKeysThisSession.insert(pendingSave.key)
            invalidCredentialKeys.remove(pendingSave.key)
            authRePromptCounts[name] = 0
            globalMessage = "Saved password for \(pendingSave.key.account) in Keychain."
        } catch {
            globalMessage = "Connected, but failed to save password: \(error.localizedDescription)"
        }
    }

    fileprivate func resetAuthRePromptCount(for name: String) {
        authRePromptCounts[name] = 0
    }

    fileprivate func recordAuthenticationFailure(for name: String) {
        sawAuthenticationFailure.insert(name)
    }

    private func handleAuthenticationFailure(for name: String) {
        guard let source = activeCredentialSources[name] else {
            return
        }

        switch source {
        case .keychain(let key):
            invalidCredentialKeys.insert(key)
            do {
                try passwordStore.deletePassword(for: key)
                globalMessage = "Saved password for \(key.account) was rejected and has been removed. Start again to re-enter it."
            } catch {
                globalMessage = "Authentication failed and the saved password could not be removed: \(error.localizedDescription)"
            }
            forgetSessionPassword(for: key)
            savedCredentialKeysThisSession.remove(key)
        case .prompted(let key):
            invalidCredentialKeys.insert(key)
            forgetSessionPassword(for: key)
            savedCredentialKeysThisSession.remove(key)
        case .none:
            break
        }
    }

    private func forgetSessionPassword(for key: TunnelCredentialKey) {
        let rejected = sessionPasswords.removeValue(forKey: key)
        let hostUserKey = key.hostUserKey
        if let rejected, sessionPasswordsByHostUser[hostUserKey] == rejected {
            sessionPasswordsByHostUser.removeValue(forKey: hostUserKey)
        }
    }

    private func shouldAutoPromptAgain(for name: String) -> Bool {
        authRePromptCounts[name, default: 0] < 3
    }

    private func uniqueDuplicateName(for baseName: String) -> String {
        let existingNames = Set(tunnels.map(\.id))
        let baseCopyName = "\(baseName)-copy"
        if !existingNames.contains(baseCopyName) {
            return baseCopyName
        }

        var index = 2
        while existingNames.contains("\(baseName)-copy-\(index)") {
            index += 1
        }
        return "\(baseName)-copy-\(index)"
    }
}

final class TunnelEventBridge: @unchecked Sendable {
    weak var owner: MenuBarViewModel?
    let tunnelName: String

    init(owner: MenuBarViewModel, tunnelName: String) {
        self.owner = owner
        self.tunnelName = tunnelName
    }

    func log(_ message: String) {
        Task { @MainActor in
            if message.localizedCaseInsensitiveContains("permission denied") ||
                message.localizedCaseInsensitiveContains("authentication failed") {
                self.owner?.recordAuthenticationFailure(for: self.tunnelName)
            }
            self.owner?.appendLog(for: self.tunnelName, message: message)
            self.owner?.updateState(for: self.tunnelName, isRunning: true, message: message)
        }
    }

    func handle(_ event: TunnelRuntimeEvent) {
        Task { @MainActor in
            switch event {
            case .starting:
                self.owner?.updateState(for: self.tunnelName, isRunning: true, state: .connecting, message: "Connecting")
            case .connected:
                self.owner?.persistPasswordIfNeeded(for: self.tunnelName)
                self.owner?.resetAuthRePromptCount(for: self.tunnelName)
                self.owner?.updateState(for: self.tunnelName, isRunning: true, state: .connected, message: "Connected")
            case .authenticationFailed(let message):
                self.owner?.recordAuthenticationFailure(for: self.tunnelName)
                self.owner?.updateState(for: self.tunnelName, isRunning: false, state: .failed, message: "Authentication failed: \(message)")
                self.owner?.globalMessage = "\(self.tunnelName): authentication failed. \(message)"
            case .exited(let code, let diagnostic):
                let message = diagnostic.map { "ssh exited \(code): \($0); retrying" } ?? "ssh exited \(code); retrying"
                self.owner?.updateState(for: self.tunnelName, isRunning: true, state: .failed, message: message)
                self.owner?.globalMessage = diagnostic.map { "\(self.tunnelName): \($0). Retrying." } ?? "\(self.tunnelName): ssh exited with code \(code). Retrying."
            case .failedToStart(let message):
                self.owner?.updateState(for: self.tunnelName, isRunning: true, state: .failed, message: "Connect failed; retrying: \(message)")
                self.owner?.globalMessage = "\(self.tunnelName): \(message). Retrying."
            case .log:
                break
            }
        }
    }

    func finish() {
        Task { @MainActor in
            self.owner?.finishTunnel(named: self.tunnelName)
        }
    }
}

struct MenuBarContent: View {
    @ObservedObject var viewModel: MenuBarViewModel
    private let menuWidth: CGFloat = 450
    private let minimumMenuHeight: CGFloat = 560

    struct EndpointGroup: Identifiable {
        let endpoint: String
        let tunnels: [MenuBarViewModel.TunnelState]

        var id: String { endpoint }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
                .padding(.horizontal, 16)
                .padding(.top, 12)
                .padding(.bottom, 10)
            Divider()
            if let draft = viewModel.editorDraft {
                TunnelEditorSheet(
                    draft: binding(for: draft),
                    suggestions: TunnelEditorSuggestions(tunnels: viewModel.tunnels.map(\.tunnel)),
                    onCancel: { viewModel.closeEditor() },
                    onSave: { viewModel.saveEditor() },
                    onDelete: { viewModel.deleteEditorTunnel() }
                )
                .padding(12)
            } else {
                if viewModel.tunnels.isEmpty {
                    emptyState
                        .padding(16)
                } else {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 10) {
                            ForEach(endpointGroups) { group in
                                VStack(alignment: .leading, spacing: 5) {
                                    EndpointHeader(group: group)

                                    VStack(alignment: .leading, spacing: 0) {
                                        ForEach(Array(group.tunnels.enumerated()), id: \.element.id) { index, tunnel in
                                            if index > 0 {
                                                Divider()
                                                    .opacity(0.34)
                                                    .padding(.leading, 42)
                                            }
                                            TunnelRow(
                                                tunnel: tunnel,
                                                onStart: { viewModel.startTunnel(named: tunnel.id) },
                                                onStop: { viewModel.stopTunnel(named: tunnel.id) },
                                                onRestart: { viewModel.restartTunnel(named: tunnel.id) },
                                                onEdit: { viewModel.openEditor(for: tunnel.id) },
                                                onDuplicate: { viewModel.duplicateTunnel(named: tunnel.id) },
                                                onDelete: { viewModel.deleteTunnel(named: tunnel.id) },
                                                onToggleAutoConnect: { viewModel.setAutoConnect(named: tunnel.id, enabled: $0) }
                                            )
                                        }
                                    }
                                    .background(
                                        RoundedRectangle(cornerRadius: 16, style: .continuous)
                                            .fill(Color(nsColor: .controlBackgroundColor).opacity(0.54))
                                    )
                                    .overlay(
                                        RoundedRectangle(cornerRadius: 16, style: .continuous)
                                            .stroke(Color.black.opacity(0.035), lineWidth: 1)
                                    )
                                    .shadow(color: Color.black.opacity(0.045), radius: 6, x: 0, y: 3)
                                }
                            }
                        }
                        .padding(.horizontal, 12)
                        .padding(.vertical, 10)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
                }
                Divider()
                footer
                    .padding(.horizontal, 12)
                    .padding(.vertical, 10)
                    .background(Color(nsColor: .controlBackgroundColor).opacity(0.42))
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .frame(width: menuWidth, height: adaptiveMenuHeight)
        .background(Color(nsColor: .windowBackgroundColor))
    }

    private var adaptiveMenuHeight: CGFloat {
        min(maximumMenuHeight, max(minimumMenuHeight, preferredMenuHeight))
    }

    private var maximumMenuHeight: CGFloat {
        let mouseLocation = NSEvent.mouseLocation
        let activeScreen = NSScreen.screens.first { screen in
            NSMouseInRect(mouseLocation, screen.frame, false)
        } ?? NSScreen.main
        let visibleHeight = activeScreen?.visibleFrame.height ?? 700
        return floor(visibleHeight * 0.80)
    }

    private var preferredMenuHeight: CGFloat {
        if viewModel.editorDraft != nil {
            return 720
        }

        guard !viewModel.tunnels.isEmpty else {
            return minimumMenuHeight
        }

        let listHeight = endpointGroups.reduce(CGFloat(0)) { total, group in
            let tunnelCount = CGFloat(group.tunnels.count)
            let dividerHeight = CGFloat(max(group.tunnels.count - 1, 0))
            let groupHeaderAndSpacing: CGFloat = 32
            let rowHeight: CGFloat = 54
            let interGroupSpacing: CGFloat = 10
            return total + groupHeaderAndSpacing + (tunnelCount * rowHeight) + dividerHeight + interGroupSpacing
        }

        let headerAndFooterChrome: CGFloat = 166
        return headerAndFooterChrome + listHeight
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 7) {
            HStack {
                if viewModel.editorDraft != nil {
                    Button("Back") {
                        viewModel.closeEditor()
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                } else {
                    Text("Burrow")
                        .font(.system(size: 20, weight: .bold))
                        .tracking(-0.45)
                }
                Spacer()
                if viewModel.editorDraft == nil {
                    HealthSummaryPill(tunnels: viewModel.tunnels)
                } else {
                    HeaderPill(text: "Editing tunnel")
                }
            }
            Text(viewModel.globalMessage)
                .font(.system(size: 11.2, weight: .semibold))
                .foregroundStyle(.secondary.opacity(0.86))
                .lineLimit(1)
                .truncationMode(.middle)
        }
    }

    private var emptyState: some View {
        VStack(alignment: .leading, spacing: 7) {
            Text("No tunnels saved.")
                .font(.system(size: 13, weight: .medium))
            Text("Create tunnels with the CLI or edit the central config, then reload here.")
                .font(.system(size: 11))
                .foregroundStyle(.secondary)
        }
    }

    private var footer: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Button {
                    viewModel.startEnabledTunnels()
                } label: {
                    Label("Start Enabled", systemImage: "play.fill")
                }
                Button {
                    viewModel.stopAll()
                } label: {
                    Label("Stop All", systemImage: "stop.fill")
                }
                Spacer()
                Button {
                    viewModel.createTunnel()
                } label: {
                    Label("New Tunnel", systemImage: "plus")
                }
                .buttonStyle(.borderedProminent)
                .tint(.black)
            }

            HStack(spacing: 8) {
                Menu {
                    Button("Reload", action: viewModel.reloadConfig)
                    Divider()
                    Button("Edit JSON", action: viewModel.openConfig)
                    Button("Reveal File", action: viewModel.revealConfigFolder)
                } label: {
                    Label("Settings", systemImage: "gearshape")
                }
                .menuStyle(.borderlessButton)

                Spacer()

                Button("Quit") {
                    viewModel.quit()
                }
            }
            .font(.system(size: 11))
        }
        .controlSize(.small)
    }

    private func binding(for draft: TunnelDraft) -> Binding<TunnelDraft> {
        Binding(
            get: { viewModel.editorDraft ?? draft },
            set: { viewModel.editorDraft = $0 }
        )
    }

    private var endpointGroups: [EndpointGroup] {
        var groups: [EndpointGroup] = []

        for tunnel in viewModel.tunnels {
            let endpoint = "\(tunnel.tunnel.host):\(String(tunnel.tunnel.sshPort))"
            if let index = groups.firstIndex(where: { $0.endpoint == endpoint }) {
                var tunnels = groups[index].tunnels
                tunnels.append(tunnel)
                groups[index] = EndpointGroup(endpoint: endpoint, tunnels: tunnels)
            } else {
                groups.append(EndpointGroup(endpoint: endpoint, tunnels: [tunnel]))
            }
        }

        return groups
    }
}

private struct EndpointHeader: View {
    let group: MenuBarContent.EndpointGroup

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: "terminal")
                .font(.system(size: 8, weight: .semibold))
                .foregroundStyle(.secondary.opacity(0.64))
                .frame(width: 17, height: 17)
                .background(
                    RoundedRectangle(cornerRadius: 6, style: .continuous)
                        .fill(Color.secondary.opacity(0.055))
                )
            Text(verbatim: group.endpoint)
                .font(.system(size: 10, weight: .bold, design: .monospaced))
                .tracking(0.15)
                .foregroundStyle(Color.secondary.opacity(0.62))
                .lineLimit(1)
                .truncationMode(.middle)
            Spacer(minLength: 4)
            EndpointHealthDots(tunnels: group.tunnels)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 1)
        .help(group.endpoint)
    }
}

private struct EndpointHealthDots: View {
    let tunnels: [MenuBarViewModel.TunnelState]

    var body: some View {
        HStack(spacing: 5) {
            if connectedCount > 0 {
                dot(.green)
            }
            if connectingCount > 0 {
                dot(.orange)
            }
            if failedCount > 0 {
                dot(.red)
            }
            Text("\(tunnels.count)")
                .font(.system(size: 10, weight: .bold))
                .foregroundStyle(.secondary.opacity(0.72))
        }
        .padding(.horizontal, 7)
        .frame(height: 20)
        .background(
            Capsule(style: .continuous)
                .fill(Color.secondary.opacity(0.055))
        )
        .help("\(connectedCount) up, \(connectingCount) starting, \(failedCount) failed, \(waitingCount) waiting")
    }

    private func dot(_ color: Color) -> some View {
        Circle()
            .fill(color)
            .frame(width: 4.5, height: 4.5)
    }

    private var connectedCount: Int {
        tunnels.filter { $0.connectionState == .connected }.count
    }

    private var connectingCount: Int {
        tunnels.filter { $0.connectionState == .connecting }.count
    }

    private var failedCount: Int {
        tunnels.filter { $0.connectionState == .failed }.count
    }

    private var waitingCount: Int {
        tunnels.filter { $0.connectionState == .disconnected }.count
    }
}

private struct HeaderPill: View {
    let text: String

    var body: some View {
        Text(text)
            .font(.system(size: 11, weight: .semibold))
            .foregroundStyle(.secondary)
            .padding(.horizontal, 10)
            .padding(.vertical, 5)
            .background(
                Capsule(style: .continuous)
                    .fill(Color(nsColor: .controlBackgroundColor))
            )
    }
}

private struct HealthSummaryPill: View {
    let tunnels: [MenuBarViewModel.TunnelState]

    var body: some View {
        HStack(spacing: 8) {
            summaryBadge(count: upCount, color: .green)
            summaryBadge(count: connectingCount, color: .orange)
            summaryBadge(count: failedCount, color: .red)
            summaryBadge(count: waitingCount, color: .gray)
        }
        .help("\(upCount) up, \(connectingCount) starting, \(failedCount) failed, \(waitingCount) waiting")
    }

    private var upCount: Int {
        tunnels.filter { $0.connectionState == .connected }.count
    }

    private var connectingCount: Int {
        tunnels.filter { $0.connectionState == .connecting }.count
    }

    private var failedCount: Int {
        tunnels.filter { $0.connectionState == .failed }.count
    }

    private var waitingCount: Int {
        tunnels.filter { $0.connectionState == .disconnected }.count
    }

    private func summaryBadge(count: Int, color: Color) -> some View {
        HStack(spacing: 5) {
            Circle()
                .fill(color)
                .frame(width: 5.5, height: 5.5)
            Text("\(count)")
                .font(.system(size: 10.5, weight: .bold))
                .foregroundStyle(color.opacity(0.82))
        }
        .padding(.horizontal, 8)
        .frame(height: 24)
        .background(
            Capsule(style: .continuous)
                .fill(color.opacity(0.10))
        )
        .overlay(
            Capsule(style: .continuous)
                .stroke(color.opacity(0.10), lineWidth: 1)
        )
    }
}

private struct CompactPressButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .scaleEffect(configuration.isPressed ? 0.965 : 1.0)
            .animation(.easeOut(duration: 0.08), value: configuration.isPressed)
    }
}

struct TunnelRow: View {
    let tunnel: MenuBarViewModel.TunnelState
    let onStart: () -> Void
    let onStop: () -> Void
    let onRestart: () -> Void
    let onEdit: () -> Void
    let onDuplicate: () -> Void
    let onDelete: () -> Void
    let onToggleAutoConnect: (Bool) -> Void
    @State private var isFailureTooltipVisible = false
    @State private var isIdentityTooltipVisible = false
    @State private var isDetailsPresented = false
    @State private var isAutoHovered = false
    @State private var isPrimaryHovered = false
    @State private var isMenuHovered = false

    var body: some View {
        HStack(alignment: .center, spacing: 10) {
            statusIndicator

            VStack(alignment: .leading, spacing: 4) {
                Text(tunnel.tunnel.name)
                    .font(.system(size: 13.4, weight: .bold))
                    .foregroundStyle(.primary.opacity(0.92))
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .layoutPriority(1)

                routeSummaryView
            }
            .layoutPriority(1)
            .contentShape(Rectangle())
            .onHover { hovering in
                withAnimation(.easeInOut(duration: 0.08)) {
                    isIdentityTooltipVisible = hovering
                }
            }
            .popover(isPresented: $isIdentityTooltipVisible, arrowEdge: .top) {
                identityTooltip
            }

            Spacer(minLength: 6)

            HStack(spacing: 5) {
                failureInfoSlot
                autoConnectButton
                primaryActionButton
                rowMenu
            }
            .frame(width: 183, alignment: .trailing)
            .layoutPriority(2)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 9)
    }

    private var statusIndicator: some View {
        ZStack {
            Circle()
                .fill(statusColor.opacity(0.10))
                .frame(width: 18, height: 18)
            Circle()
                .fill(statusColor)
                .frame(width: 8, height: 8)
        }
    }

    private var endpointText: String {
        "\(tunnel.tunnel.host):\(String(tunnel.tunnel.sshPort))"
    }

    private var fullRouteSummary: String {
        tunnel.tunnel.forwards.map { forward in
            switch forward.kind {
            case .local:
                let destinationHost = forward.destinationHost ?? "?"
                let destinationPort = forward.destinationPort.map(String.init) ?? "?"
                return "\(String(forward.listenPort)) -> \(destinationHost):\(destinationPort) @ \(endpointText)"
            case .remote:
                let destinationHost = forward.destinationHost ?? "?"
                let destinationPort = forward.destinationPort.map(String.init) ?? "?"
                return "\(destinationHost):\(destinationPort) <- \(String(forward.listenPort)) @ \(endpointText)"
            case .dynamic:
                return "socks \(String(forward.listenPort)) @ \(endpointText)"
            }
        }
        .joined(separator: "  •  ")
    }

    private var identityTooltip: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(tunnel.tunnel.name)
                .font(.system(size: 11.5, weight: .semibold))
                .foregroundStyle(.primary)
                .lineLimit(1)
            Text(fullRouteSummary)
                .font(.system(size: 11, weight: .medium, design: .monospaced))
                .monospacedDigit()
                .foregroundStyle(.secondary)
                .lineLimit(3)
        }
        .padding(.horizontal, 9)
        .padding(.vertical, 7)
        .frame(maxWidth: 330, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 9, style: .continuous)
                .fill(Color(nsColor: .windowBackgroundColor))
                .shadow(color: .black.opacity(0.14), radius: 8, x: 0, y: 4)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 9, style: .continuous)
                .stroke(Color.black.opacity(0.08), lineWidth: 1)
        )
    }

    @ViewBuilder
    private var routeSummaryView: some View {
        if tunnel.tunnel.forwards.count == 1, let forward = tunnel.tunnel.forwards.first {
            routeView(for: forward)
                .help(fullRouteText(for: forward))
        } else {
            Text(verbatim: compactRouteSummary)
                .font(.system(size: 11.2, weight: .medium, design: .monospaced))
                .monospacedDigit()
                .foregroundStyle(.secondary.opacity(0.95))
                .lineLimit(1)
                .truncationMode(.tail)
                .help(fullRouteSummary)
        }
    }

    @ViewBuilder
    private func routeView(for forward: ForwardSpec) -> some View {
        switch forward.kind {
        case .local:
            routeLine(
                first: String(forward.listenPort),
                second: compactDestinationText(for: forward),
                arrow: "chevron.right"
            )
        case .remote:
            routeLine(
                first: compactDestinationText(for: forward),
                second: String(forward.listenPort),
                arrow: "chevron.left"
            )
        case .dynamic:
            HStack(spacing: 4) {
                Text(verbatim: "SOCKS")
                Text(verbatim: String(forward.listenPort))
            }
            .font(.system(size: 11.2, weight: .medium, design: .monospaced))
            .monospacedDigit()
            .foregroundStyle(.secondary.opacity(0.95))
            .lineLimit(1)
            .truncationMode(.tail)
        }
    }

    private func routeLine(first: String, second: String, arrow: String) -> some View {
        HStack(spacing: 7) {
            Text(verbatim: first)
                .font(.system(size: 11.2, weight: .bold, design: .monospaced))
                .monospacedDigit()
                .foregroundStyle(.secondary.opacity(0.95))
                .lineLimit(1)
                .fixedSize(horizontal: true, vertical: false)
                .padding(.horizontal, 6)
                .frame(height: 21)
                .background(
                    RoundedRectangle(cornerRadius: 5, style: .continuous)
                        .fill(Color.secondary.opacity(0.065))
                )

            Image(systemName: arrow)
                .font(.system(size: 8, weight: .bold))
                .foregroundStyle(.tertiary)

            Text(verbatim: second)
                .font(.system(size: 11.2, weight: .semibold, design: .monospaced))
                .monospacedDigit()
                .foregroundStyle(.secondary.opacity(0.88))
                .lineLimit(1)
                .truncationMode(.tail)
        }
    }

    private var compactRouteSummary: String {
        tunnel.tunnel.forwards.map { forward in
            switch forward.kind {
            case .local:
                return "\(String(forward.listenPort)) -> \(compactDestinationText(for: forward))"
            case .remote:
                return "\(compactDestinationText(for: forward)) <- \(String(forward.listenPort))"
            case .dynamic:
                return "SOCKS \(String(forward.listenPort))"
            }
        }
        .joined(separator: "  •  ")
    }

    private func compactDestinationText(for forward: ForwardSpec) -> String {
        let destinationHost = forward.destinationHost ?? "?"
        let destinationPort = forward.destinationPort.map(String.init) ?? "?"
        if isLoopbackHost(destinationHost) {
            return destinationPort
        }
        return "\(destinationHost):\(destinationPort)"
    }

    private func fullRouteText(for forward: ForwardSpec) -> String {
        switch forward.kind {
        case .local:
            let destinationHost = forward.destinationHost ?? "?"
            let destinationPort = forward.destinationPort.map(String.init) ?? "?"
            return "\(String(forward.listenPort)) -> \(destinationHost):\(destinationPort) @ \(endpointText)"
        case .remote:
            let destinationHost = forward.destinationHost ?? "?"
            let destinationPort = forward.destinationPort.map(String.init) ?? "?"
            return "\(destinationHost):\(destinationPort) <- \(String(forward.listenPort)) @ \(endpointText)"
        case .dynamic:
            return "SOCKS \(String(forward.listenPort)) @ \(endpointText)"
        }
    }

    private func isLoopbackHost(_ host: String) -> Bool {
        let normalized = host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return normalized == "localhost" || normalized == "127.0.0.1" || normalized == "::1"
    }

    private var statusColor: Color {
        switch tunnel.connectionState {
        case .connected:
            return .green
        case .connecting:
            return .orange
        case .disconnected:
            return .gray
        case .failed:
            return .red
        }
    }

    @ViewBuilder
    private var rowMenu: some View {
        Menu {
            Button("Details") {
                isDetailsPresented = true
            }
            Divider()
            Button("Restart", action: onRestart)
            Button("Edit", action: onEdit)
            Button("Duplicate", action: onDuplicate)
            Divider()
            Button("Delete", role: .destructive, action: onDelete)
        } label: {
            Image(systemName: "ellipsis")
                .font(.system(size: 11.5, weight: .heavy))
                .foregroundStyle(isMenuHovered ? Color.primary.opacity(0.76) : Color.secondary.opacity(0.60))
                .frame(width: 20, height: 28)
                .background(
                    Circle()
                        .fill(Color.secondary.opacity(isMenuHovered ? 0.10 : 0.0))
                )
        }
        .menuStyle(.borderlessButton)
        .menuIndicator(.hidden)
        .onHover { hovering in
            withAnimation(.easeOut(duration: 0.12)) {
                isMenuHovered = hovering
            }
        }
        .frame(width: 20, height: 28, alignment: .trailing)
        .popover(isPresented: $isDetailsPresented, arrowEdge: .trailing) {
            TunnelDetailsPopover(
                tunnel: tunnel,
                routeSummary: fullRouteSummary,
                commandText: sshCommandText,
                failurePresentation: failurePresentation
            )
        }
    }

    private var autoConnectButton: some View {
        Button {
            onToggleAutoConnect(!tunnel.isConfiguredEnabled)
        } label: {
            HStack(spacing: 3) {
                Image(systemName: tunnel.isConfiguredEnabled ? "bolt.fill" : "bolt.slash.fill")
                    .font(.system(size: 10, weight: .semibold))
                Text("Auto")
                    .font(.system(size: 10.5, weight: .bold))
                    .lineLimit(1)
                    .minimumScaleFactor(0.85)
            }
                .frame(width: 56, height: 28)
                .foregroundStyle(tunnel.isConfiguredEnabled ? Color(red: 0.27, green: 0.20, blue: 0.83) : Color.secondary)
                .background(
                    Capsule(style: .continuous)
                        .fill(
                            tunnel.isConfiguredEnabled
                                ? Color(red: 0.94, green: 0.95, blue: 1.0).opacity(isAutoHovered ? 1.0 : 0.82)
                                : Color.secondary.opacity(isAutoHovered ? 0.085 : 0.055)
                        )
                )
                .overlay(
                    Capsule(style: .continuous)
                        .stroke(tunnel.isConfiguredEnabled ? Color(red: 0.74, green: 0.80, blue: 1.0).opacity(isAutoHovered ? 0.82 : 0.52) : Color.secondary.opacity(isAutoHovered ? 0.16 : 0.10), lineWidth: 1)
                )
                .shadow(color: Color(red: 0.27, green: 0.20, blue: 0.83).opacity(tunnel.isConfiguredEnabled ? (isAutoHovered ? 0.16 : 0.07) : 0), radius: isAutoHovered ? 8 : 5, x: 0, y: isAutoHovered ? 4 : 2)
                .scaleEffect(isAutoHovered ? 1.015 : 1.0)
        }
        .buttonStyle(CompactPressButtonStyle())
        .onHover { hovering in
            withAnimation(.easeOut(duration: 0.12)) {
                isAutoHovered = hovering
            }
        }
        .frame(width: 56, height: 28)
        .help(tunnel.isConfiguredEnabled ? "Auto-connect enabled" : "Auto-connect disabled")
    }

    @ViewBuilder
    private var primaryActionButton: some View {
        if tunnel.isRunning {
            Button {
                onStop()
            } label: {
                Text("Stop")
                    .font(.system(size: 11, weight: .bold))
                    .lineLimit(1)
                    .minimumScaleFactor(0.85)
                    .frame(width: 68, height: 28)
                    .foregroundStyle(isPrimaryHovered ? Color(red: 0.82, green: 0.10, blue: 0.08) : Color.primary.opacity(0.82))
                    .background(
                        Capsule(style: .continuous)
                            .fill(isPrimaryHovered ? Color(red: 1.0, green: 0.96, blue: 0.955) : Color(nsColor: .windowBackgroundColor))
                    )
                    .overlay(
                        Capsule(style: .continuous)
                            .stroke(isPrimaryHovered ? Color(red: 0.95, green: 0.20, blue: 0.18).opacity(0.24) : Color.secondary.opacity(0.18), lineWidth: 1)
                    )
                    .shadow(color: Color.black.opacity(isPrimaryHovered ? 0.14 : 0.08), radius: isPrimaryHovered ? 6 : 4, x: 0, y: isPrimaryHovered ? 3 : 2)
                    .scaleEffect(isPrimaryHovered ? 1.015 : 1.0)
            }
            .buttonStyle(CompactPressButtonStyle())
            .onHover { hovering in
                withAnimation(.easeOut(duration: 0.12)) {
                    isPrimaryHovered = hovering
                }
            }
            .frame(width: 68, alignment: .trailing)
        } else {
            Button {
                onStart()
            } label: {
                Text("Connect")
                    .font(.system(size: 11, weight: .bold))
                    .lineLimit(1)
                    .minimumScaleFactor(0.82)
                    .frame(width: 68, height: 28)
                    .foregroundStyle(.white)
                    .background(
                        Capsule(style: .continuous)
                            .fill(
                                LinearGradient(
                                    colors: [
                                        isPrimaryHovered ? Color(red: 0.33, green: 0.24, blue: 0.92) : Color(red: 0.26, green: 0.19, blue: 0.84),
                                        isPrimaryHovered ? Color(red: 0.12, green: 0.49, blue: 1.0) : Color(red: 0.19, green: 0.42, blue: 0.94),
                                    ],
                                    startPoint: .leading,
                                    endPoint: .trailing
                                )
                            )
                    )
                    .shadow(color: Color(red: 0.26, green: 0.19, blue: 0.84).opacity(isPrimaryHovered ? 0.32 : 0.20), radius: isPrimaryHovered ? 9 : 7, x: 0, y: isPrimaryHovered ? 5 : 4)
                    .scaleEffect(isPrimaryHovered ? 1.015 : 1.0)
            }
            .buttonStyle(CompactPressButtonStyle())
            .onHover { hovering in
                withAnimation(.easeOut(duration: 0.12)) {
                    isPrimaryHovered = hovering
                }
            }
            .frame(width: 68, alignment: .trailing)
        }
    }

    private var failureInfoSlot: some View {
        Group {
            if failurePresentation != nil {
                Image(systemName: "info.circle.fill")
                    .font(.system(size: 10.5, weight: .semibold))
                    .foregroundStyle(Color(red: 1.0, green: 0.36, blue: 0.35))
                    .frame(width: 24, height: 28)
                    .background(
                        RoundedRectangle(cornerRadius: 11, style: .continuous)
                            .fill(Color(red: 1.0, green: 0.36, blue: 0.35).opacity(0.14))
                    )
            } else {
                Color.clear
            }
        }
        .frame(width: 24, height: 28)
        .contentShape(Rectangle())
        .onHover { hovering in
            if failurePresentation == nil {
                isFailureTooltipVisible = false
            } else {
                withAnimation(.easeInOut(duration: 0.08)) {
                    isFailureTooltipVisible = hovering
                }
            }
        }
        .popover(isPresented: $isFailureTooltipVisible, arrowEdge: .top) {
            if let presentation = failurePresentation {
                failureTooltip(presentation)
            }
        }
    }

    private func failureTooltip(_ presentation: TunnelFailurePresentation) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(presentation.codeLine)
                .font(.system(size: 10, weight: .semibold, design: .monospaced))
                .foregroundStyle(presentation.color)
            Text(presentation.hintLine)
                .font(.system(size: 10))
                .foregroundStyle(Color(red: 0.36, green: 0.14, blue: 0.12))
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 7)
        .frame(width: 220, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 9, style: .continuous)
                .fill(Color(nsColor: .windowBackgroundColor))
                .shadow(color: .black.opacity(0.14), radius: 8, x: 0, y: 4)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 9, style: .continuous)
                .stroke(Color.black.opacity(0.08), lineWidth: 1)
        )
    }

    private var failurePresentation: TunnelFailurePresentation? {
        TunnelFailureClassifier.presentation(for: tunnel)
    }

    private var sshCommandText: String {
        let prepared = (try? TunnelLaunchPreparer.prepare(tunnel.tunnel)) ?? tunnel.tunnel
        return SSHCommandBuilder.render(prepared)
    }
}

private struct TunnelDetailsPopover: View {
    let tunnel: MenuBarViewModel.TunnelState
    let routeSummary: String
    let commandText: String
    let failurePresentation: TunnelFailurePresentation?

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 7) {
                Circle()
                    .fill(statusColor)
                    .frame(width: 7, height: 7)
                Text(tunnel.tunnel.name)
                    .font(.system(size: 13, weight: .semibold))
                    .lineLimit(1)
                    .truncationMode(.middle)
                Spacer()
                Text(statusText)
                    .font(.system(size: 10, weight: .semibold))
                    .foregroundStyle(.secondary)
            }

            VStack(alignment: .leading, spacing: 5) {
                detailRow("Endpoint", "\(tunnel.tunnel.host):\(String(tunnel.tunnel.sshPort))")
                detailRow("Route", routeSummary)
                detailRow("Auto", tunnel.isConfiguredEnabled ? "enabled" : "disabled")
                detailRow("Credential", credentialText)
                detailRow("Probe", probeText)
            }

            if let failurePresentation {
                Divider()
                VStack(alignment: .leading, spacing: 3) {
                    Text(failurePresentation.codeLine)
                        .font(.system(size: 10.5, weight: .semibold, design: .monospaced))
                        .foregroundStyle(failurePresentation.color)
                    Text(failurePresentation.hintLine)
                        .font(.system(size: 10.5))
                        .foregroundStyle(.secondary)
                }
            }

            Divider()

            VStack(alignment: .leading, spacing: 4) {
                Text("Recent log")
                    .font(.system(size: 10, weight: .semibold))
                    .foregroundStyle(.secondary)
                Text(recentLogText)
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(.primary.opacity(0.78))
                    .lineLimit(8)
                    .textSelection(.enabled)
            }

            VStack(alignment: .leading, spacing: 4) {
                Text("SSH command")
                    .font(.system(size: 10, weight: .semibold))
                    .foregroundStyle(.secondary)
                Text(commandText)
                    .font(.system(size: 9.5, design: .monospaced))
                    .foregroundStyle(.primary.opacity(0.72))
                    .lineLimit(5)
                    .textSelection(.enabled)
            }
        }
        .padding(12)
        .frame(width: 340, alignment: .leading)
    }

    private func detailRow(_ label: String, _ value: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text(label)
                .font(.system(size: 10, weight: .semibold))
                .foregroundStyle(.secondary)
                .frame(width: 62, alignment: .leading)
            Text(value)
                .font(.system(size: 10.5, design: .monospaced))
                .foregroundStyle(.primary.opacity(0.82))
                .lineLimit(2)
                .truncationMode(.middle)
                .textSelection(.enabled)
        }
    }

    private var statusColor: Color {
        switch tunnel.connectionState {
        case .connected:
            return .green
        case .connecting:
            return .orange
        case .disconnected:
            return .gray
        case .failed:
            return .red
        }
    }

    private var statusText: String {
        switch tunnel.connectionState {
        case .connected:
            return "connected"
        case .connecting:
            return "connecting"
        case .disconnected:
            return "stopped"
        case .failed:
            return failurePresentation?.category ?? "failed"
        }
    }

    private var credentialText: String {
        guard let user = tunnel.tunnel.user, !user.isEmpty else {
            return "none"
        }
        return "\(user)@\(tunnel.tunnel.host):\(String(tunnel.tunnel.sshPort))"
    }

    private var probeText: String {
        switch tunnel.connectionState {
        case .connected:
            return "local forward reachable"
        case .connecting:
            return "checking local forward"
        case .failed:
            return failurePresentation?.category ?? "failed"
        case .disconnected:
            return "not running"
        }
    }

    private var recentLogText: String {
        if tunnel.recentLogs.isEmpty {
            return tunnel.lastMessage.isEmpty ? "No recent log" : tunnel.lastMessage
        }
        return tunnel.recentLogs.suffix(20).joined(separator: "\n")
    }
}

private struct TunnelFailurePresentation {
    let category: String
    let codeLine: String
    let hintLine: String
    let color: Color
}

private enum TunnelFailureClassifier {
    static func presentation(for tunnel: MenuBarViewModel.TunnelState) -> TunnelFailurePresentation? {
        guard case .failed = tunnel.connectionState else {
            return nil
        }

        let message = tunnel.lastMessage.trimmingCharacters(in: .whitespacesAndNewlines)
        let lowercased = message.lowercased()

        if containsAny(lowercased, ["authentication failed", "permission denied", "incorrect password", "invalid password", "access denied"]) {
            return TunnelFailurePresentation(
                category: "auth failed",
                codeLine: "authentication failed",
                hintLine: "Check the saved username or password for this endpoint.",
                color: Color(red: 0.68, green: 0.12, blue: 0.10)
            )
        }

        if containsAny(lowercased, ["address already in use", "cannot listen to port", "could not request local forwarding"]) {
            return TunnelFailurePresentation(
                category: "port conflict",
                codeLine: "local port unavailable",
                hintLine: "Another process is already listening on this local port.",
                color: Color(red: 0.72, green: 0.18, blue: 0.10)
            )
        }

        if containsAny(lowercased, ["could not resolve hostname", "nodename nor servname", "temporary failure in name resolution"]) {
            return TunnelFailurePresentation(
                category: "dns issue",
                codeLine: "host not resolvable",
                hintLine: "Check VPN, DNS, or the current network environment.",
                color: Color(red: 0.68, green: 0.12, blue: 0.10)
            )
        }

        if containsAny(lowercased, ["operation timed out", "connection timed out", "network is unreachable", "no route to host", "connection refused", "connection closed", "connection reset", "broken pipe"]) {
            return TunnelFailurePresentation(
                category: "network issue",
                codeLine: "network unavailable",
                hintLine: "Check VPN, remote reachability, or firewall rules.",
                color: Color(red: 0.68, green: 0.12, blue: 0.10)
            )
        }

        if containsAny(lowercased, ["host key verification failed", "remote host identification has changed"]) {
            return TunnelFailurePresentation(
                category: "host key issue",
                codeLine: "host key rejected",
                hintLine: "Review the known-hosts entry for this endpoint.",
                color: Color(red: 0.68, green: 0.12, blue: 0.10)
            )
        }

        if lowercased.contains("255") {
            return TunnelFailurePresentation(
                category: "ssh exited",
                codeLine: "ssh exited 255",
                hintLine: "Usually VPN, DNS, host reachability, or SSH policy.",
                color: Color(red: 0.68, green: 0.12, blue: 0.10)
            )
        }

        if containsAny(lowercased, ["not running", "stopped"]) {
            return TunnelFailurePresentation(
                category: "stopped",
                codeLine: "tunnel stopped",
                hintLine: "Start the tunnel again to restore the forward.",
                color: .secondary
            )
        }

        return TunnelFailurePresentation(
            category: "failed",
            codeLine: message.isEmpty ? "connection failed" : message,
            hintLine: "Open details for the SSH command and last message.",
            color: Color(red: 0.68, green: 0.12, blue: 0.10)
        )
    }

    private static func containsAny(_ text: String, _ needles: [String]) -> Bool {
        needles.contains { text.contains($0) }
    }
}

struct TunnelEditorSuggestions {
    let tunnels: [TunnelConfig]
    let hosts: [String]
    let users: [String]
    let sshPorts: [String]
    let identityFiles: [String]
    let jumpHosts: [String]
    let bindAddresses: [String]
    let destinationHosts: [String]
    let destinationPorts: [String]
    let nextAvailableLocalPort: Int

    init(tunnels: [TunnelConfig]) {
        self.tunnels = tunnels
        self.hosts = Self.ranked(tunnels.map(\.host))
        self.users = Self.ranked(tunnels.compactMap(\.user), appending: [NSUserName()])
        self.sshPorts = Self.ranked(tunnels.map { String($0.sshPort) }, appending: ["22"])
        self.identityFiles = Self.ranked(tunnels.compactMap(\.identityFile), appending: Self.commonIdentityFiles())
        self.jumpHosts = Self.ranked(tunnels.compactMap(\.jumpHost))

        let forwards = tunnels.flatMap(\.forwards)
        self.bindAddresses = Self.ranked(forwards.compactMap(\.bindAddress), appending: ["localhost", "127.0.0.1"])
        self.destinationHosts = Self.ranked(forwards.compactMap(\.destinationHost), appending: ["localhost", "127.0.0.1"])
        self.destinationPorts = Self.ranked(
            forwards.compactMap { $0.destinationPort.map(String.init) },
            appending: ["3000", "8888", "5432", "8000", "8080"]
        )
        self.nextAvailableLocalPort = Self.nextLocalPort(after: forwards)
    }

    func preferredSSHPort(for host: String) -> String? {
        let normalizedHost = normalized(host)
        return Self.ranked(
            tunnels
                .filter { normalized($0.host) == normalizedHost }
                .map { String($0.sshPort) }
        )
        .first
    }

    func preferredUser(for host: String, sshPort: String) -> String? {
        let normalizedHost = normalized(host)
        let normalizedPort = sshPort.trimmingCharacters(in: .whitespacesAndNewlines)
        let exact = tunnels
            .filter { normalized($0.host) == normalizedHost && String($0.sshPort) == normalizedPort }
            .compactMap(\.user)

        if let user = Self.ranked(exact).first {
            return user
        }

        return Self.ranked(
            tunnels
                .filter { normalized($0.host) == normalizedHost }
                .compactMap(\.user)
        )
        .first
    }

    func preferredIdentity(for host: String, user: String) -> String? {
        let normalizedHost = normalized(host)
        let normalizedUser = normalized(user)
        let exact = tunnels
            .filter { normalized($0.host) == normalizedHost && normalized($0.user ?? "") == normalizedUser }
            .compactMap(\.identityFile)

        if let identity = Self.ranked(exact).first {
            return identity
        }

        return Self.ranked(
            tunnels
                .filter { normalized($0.host) == normalizedHost }
                .compactMap(\.identityFile)
        )
        .first
    }

    func preferredJumpHost(for host: String) -> String? {
        let normalizedHost = normalized(host)
        return Self.ranked(
            tunnels
                .filter { normalized($0.host) == normalizedHost }
                .compactMap(\.jumpHost)
        )
        .first
    }

    private func normalized(_ value: String) -> String {
        value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }

    private static func ranked(_ values: [String], appending defaults: [String] = []) -> [String] {
        var counts: [String: Int] = [:]
        var firstSeen: [String: Int] = [:]
        var canonical: [String: String] = [:]

        for value in values {
            let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else { continue }
            let key = trimmed.lowercased()
            counts[key, default: 0] += 1
            if firstSeen[key] == nil {
                firstSeen[key] = firstSeen.count
                canonical[key] = trimmed
            }
        }

        let rankedValues = counts.keys.sorted { left, right in
            let leftCount = counts[left, default: 0]
            let rightCount = counts[right, default: 0]
            if leftCount != rightCount {
                return leftCount > rightCount
            }
            return firstSeen[left, default: 0] < firstSeen[right, default: 0]
        }
        .compactMap { canonical[$0] }

        return rankedValues + defaults.filter { defaultValue in
            !rankedValues.contains { $0.caseInsensitiveCompare(defaultValue) == .orderedSame }
        }
    }

    private static func commonIdentityFiles() -> [String] {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let candidates = [
            "\(home)/.ssh/id_ed25519",
            "\(home)/.ssh/id_rsa",
            "~/.ssh/id_ed25519",
            "~/.ssh/id_rsa",
        ]
        return candidates.filter { path in
            if path.hasPrefix("~") {
                return true
            }
            return FileManager.default.fileExists(atPath: path)
        }
    }

    private static func nextLocalPort(after forwards: [ForwardSpec]) -> Int {
        let used = Set(forwards.map(\.listenPort))
        var candidate = max(8875, (used.filter { $0 >= 1024 }.max() ?? 8874) + 1)
        while used.contains(candidate) {
            candidate += 1
        }
        return candidate
    }
}

struct TunnelDraft: Identifiable {
    struct ForwardDraft: Identifiable {
        let id: UUID
        var kind: ForwardSpec.Kind
        var bindAddress: String
        var listenPort: String
        var destinationHost: String
        var destinationPort: String

        init(
            id: UUID = UUID(),
            kind: ForwardSpec.Kind = .local,
            bindAddress: String = "",
            listenPort: String = "",
            destinationHost: String = "",
            destinationPort: String = ""
        ) {
            self.id = id
            self.kind = kind
            self.bindAddress = bindAddress
            self.listenPort = listenPort
            self.destinationHost = destinationHost
            self.destinationPort = destinationPort
        }

        init(forward: ForwardSpec) {
            self.id = UUID()
            self.kind = forward.kind
            self.bindAddress = forward.bindAddress ?? ""
            self.listenPort = String(forward.listenPort)
            self.destinationHost = forward.destinationHost ?? ""
            self.destinationPort = forward.destinationPort.map(String.init) ?? ""
        }

        func toForwardSpec() throws -> ForwardSpec {
            guard let listenPortValue = Int(listenPort), listenPortValue > 0 else {
                throw DraftError("Listen port must be a valid integer.")
            }

            switch kind {
            case .dynamic:
                return ForwardSpec(
                    kind: .dynamic,
                    bindAddress: bindAddress.nonEmptyValue,
                    listenPort: listenPortValue
                )
            case .local, .remote:
                guard !destinationHost.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                    throw DraftError("Destination host is required for local and remote forwards.")
                }
                guard let destinationPortValue = Int(destinationPort), destinationPortValue > 0 else {
                    throw DraftError("Destination port must be a valid integer.")
                }
                return ForwardSpec(
                    kind: kind,
                    bindAddress: bindAddress.nonEmptyValue,
                    listenPort: listenPortValue,
                    destinationHost: destinationHost.trimmingCharacters(in: .whitespacesAndNewlines),
                    destinationPort: destinationPortValue
                )
            }
        }
    }

    let id: UUID
    let originalName: String?
    var name: String
    var host: String
    var user: String
    var sshPort: String
    var identityFile: String
    var jumpHost: String
    var serverAliveInterval: String
    var serverAliveCountMax: String
    var reconnectDelaySeconds: String
    var enabled: Bool
    var extraSSHOptionsText: String
    var forwards: [ForwardDraft]

    init(tunnel: TunnelConfig, originalName: String?) {
        self.id = UUID()
        self.originalName = originalName
        self.name = tunnel.name
        self.host = tunnel.host
        self.user = tunnel.user ?? ""
        self.sshPort = String(tunnel.sshPort)
        self.identityFile = tunnel.identityFile ?? ""
        self.jumpHost = tunnel.jumpHost ?? ""
        self.serverAliveInterval = String(tunnel.serverAliveInterval)
        self.serverAliveCountMax = String(tunnel.serverAliveCountMax)
        self.reconnectDelaySeconds = String(tunnel.reconnectDelaySeconds)
        self.enabled = tunnel.enabled
        self.extraSSHOptionsText = tunnel.extraSSHOptions.joined(separator: "\n")
        self.forwards = tunnel.forwards.map(ForwardDraft.init)
    }

    static func newTunnel(from existingTunnels: [TunnelConfig] = []) -> TunnelDraft {
        let suggestions = TunnelEditorSuggestions(tunnels: existingTunnels)
        let localPort = suggestions.nextAvailableLocalPort
        let destinationPort = suggestions.destinationPorts.first ?? "3000"
        let defaultName = uniqueName(
            base: "tunnel-\(localPort)-web\(destinationPort)",
            existingNames: existingTunnels.map(\.name)
        )

        return TunnelDraft(
            tunnel: TunnelConfig(
                name: defaultName,
                host: suggestions.hosts.first ?? "",
                user: suggestions.users.first,
                sshPort: Int(suggestions.sshPorts.first ?? "22") ?? 22,
                identityFile: existingTunnels.compactMap(\.identityFile).first,
                jumpHost: existingTunnels.compactMap(\.jumpHost).first,
                forwards: [
                    ForwardSpec(
                        kind: .local,
                        listenPort: localPort,
                        destinationHost: suggestions.destinationHosts.first ?? "localhost",
                        destinationPort: Int(destinationPort) ?? 3000
                    ),
                ],
                enabled: true
            ),
            originalName: nil
        )
    }

    private static func uniqueName(base: String, existingNames: [String]) -> String {
        let existing = Set(existingNames)
        guard !existing.contains(base) else {
            var suffix = 2
            while existing.contains("\(base)-\(suffix)") {
                suffix += 1
            }
            return "\(base)-\(suffix)"
        }
        return base
    }

    func toTunnelConfig() throws -> TunnelConfig {
        let trimmedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedHost = host.trimmingCharacters(in: .whitespacesAndNewlines)

        guard !trimmedName.isEmpty else {
            throw DraftError("Tunnel name is required.")
        }
        guard !trimmedHost.isEmpty else {
            throw DraftError("Host is required.")
        }
        guard let sshPortValue = Int(sshPort), sshPortValue > 0 else {
            throw DraftError("SSH port must be a valid integer.")
        }
        guard let aliveIntervalValue = Int(serverAliveInterval), aliveIntervalValue >= 0 else {
            throw DraftError("Server alive interval must be a valid integer.")
        }
        guard let aliveCountValue = Int(serverAliveCountMax), aliveCountValue >= 0 else {
            throw DraftError("Server alive count max must be a valid integer.")
        }
        guard let reconnectDelayValue = Int(reconnectDelaySeconds), reconnectDelayValue >= 0 else {
            throw DraftError("Reconnect delay must be a valid integer.")
        }

        let cleanedForwards = try forwards.map { try $0.toForwardSpec() }
        guard !cleanedForwards.isEmpty else {
            throw DraftError("At least one forward is required.")
        }

        let sshOptions = extraSSHOptionsText
            .split(whereSeparator: \.isNewline)
            .map { String($0).trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }

        return TunnelConfig(
            name: trimmedName,
            host: trimmedHost,
            user: user.nonEmptyValue,
            sshPort: sshPortValue,
            identityFile: identityFile.nonEmptyValue,
            jumpHost: jumpHost.nonEmptyValue,
            forwards: cleanedForwards,
            serverAliveInterval: aliveIntervalValue,
            serverAliveCountMax: aliveCountValue,
            reconnectDelaySeconds: reconnectDelayValue,
            enabled: enabled,
            extraSSHOptions: sshOptions
        )
    }
}

struct TunnelEditorSheet: View {
    @Binding var draft: TunnelDraft
    let suggestions: TunnelEditorSuggestions
    let onCancel: () -> Void
    let onSave: () -> Void
    let onDelete: () -> Void
    @State private var isAdvancedExpanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .firstTextBaseline) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(draft.originalName == nil ? "New Tunnel" : "Edit Tunnel")
                        .font(.system(size: 16, weight: .bold))
                    Text("Common settings first. Advanced SSH knobs stay tucked away.")
                        .font(.system(size: 10.5))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
                Spacer()
                Toggle("Auto", isOn: $draft.enabled)
                    .toggleStyle(.switch)
                    .controlSize(.small)
                    .help("Connect this tunnel when Burrow launches")
            }

            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    endpointSection
                    forwardsSection
                    advancedSection
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
        .onChange(of: draft.host) { _ in
            applyEndpointGuess(overwrite: false)
        }
        .onChange(of: draft.sshPort) { _ in
            applyEndpointGuess(overwrite: false)
        }
    }

    private var endpointSection: some View {
        EditorSection(
            title: "Endpoint",
            subtitle: "Pick a known SSH host or type a new one."
        ) {
            Grid(alignment: .leading, horizontalSpacing: 10, verticalSpacing: 8) {
                GridRow {
                    editorLabel("Name")
                    TextField("prod-db", text: $draft.name)
                        .textFieldStyle(.roundedBorder)
                }
                GridRow {
                    editorLabel("Host")
                    SuggestingTextField(
                        placeholder: "bastion.example.com",
                        text: $draft.host,
                        suggestions: suggestions.hosts
                    )
                }
                GridRow {
                    editorLabel("User")
                    SuggestingTextField(
                        placeholder: "alice",
                        text: $draft.user,
                        suggestions: suggestions.users
                    )
                }
                GridRow {
                    editorLabel("SSH Port")
                    HStack(spacing: 8) {
                        SuggestingTextField(
                            placeholder: "22",
                            text: $draft.sshPort,
                            suggestions: suggestions.sshPorts
                        )
                        .frame(width: 92)

                        Button {
                            applyEndpointGuess(overwrite: true)
                        } label: {
                            Label("Autofill", systemImage: "wand.and.stars")
                        }
                        .buttonStyle(.bordered)
                        .controlSize(.small)
                        .disabled(draft.host.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                        .help("Fill user, port, identity, and jump host from matching saved tunnels")

                        Spacer()
                    }
                }
            }
        }
    }

    private var forwardsSection: some View {
        EditorSection(
            title: "Forward",
            subtitle: "The usual case is local port -> destination service."
        ) {
            HStack {
                Text("\(draft.forwards.count) route\(draft.forwards.count == 1 ? "" : "s")")
                    .font(.system(size: 10.5, weight: .semibold))
                    .foregroundStyle(.secondary)
                Spacer()
                Button("Add Forward") {
                    draft.forwards.append(defaultForwardDraft())
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
            }

            ForEach($draft.forwards) { $forward in
                ForwardEditorCard(
                    forward: $forward,
                    suggestions: suggestions,
                    canRemove: draft.forwards.count > 1,
                    onRemove: {
                        draft.forwards.removeAll { $0.id == forward.id }
                    }
                )
            }
        }
    }

    private var advancedSection: some View {
        DisclosureGroup(isExpanded: $isAdvancedExpanded) {
            VStack(alignment: .leading, spacing: 10) {
                Grid(alignment: .leading, horizontalSpacing: 10, verticalSpacing: 8) {
                    GridRow {
                        editorLabel("Identity")
                        SuggestingTextField(
                            placeholder: "~/.ssh/id_ed25519",
                            text: $draft.identityFile,
                            suggestions: suggestions.identityFiles
                        )
                    }
                    GridRow {
                        editorLabel("Jump Host")
                        SuggestingTextField(
                            placeholder: "jumper.example.com",
                            text: $draft.jumpHost,
                            suggestions: suggestions.jumpHosts
                        )
                    }
                    GridRow {
                        editorLabel("Keepalive")
                        HStack(spacing: 6) {
                            compactTextField("30", text: $draft.serverAliveInterval, width: 58)
                            Text("sec x")
                                .font(.system(size: 10.5))
                                .foregroundStyle(.secondary)
                            compactTextField("3", text: $draft.serverAliveCountMax, width: 44)
                            Text("tries")
                                .font(.system(size: 10.5))
                                .foregroundStyle(.secondary)
                            Spacer()
                        }
                    }
                    GridRow {
                        editorLabel("Reconnect")
                        HStack(spacing: 6) {
                            compactTextField("5", text: $draft.reconnectDelaySeconds, width: 58)
                            Text("seconds")
                                .font(.system(size: 10.5))
                                .foregroundStyle(.secondary)
                            Spacer()
                        }
                    }
                }

                VStack(alignment: .leading, spacing: 5) {
                    Text("Extra SSH Options")
                        .font(.system(size: 10.5, weight: .semibold))
                        .foregroundStyle(.secondary)
                    TextEditor(text: $draft.extraSSHOptionsText)
                        .font(.system(size: 11, design: .monospaced))
                        .frame(minHeight: 76)
                        .overlay(
                            RoundedRectangle(cornerRadius: 8)
                                .stroke(Color.secondary.opacity(0.16))
                        )
                }
            }
            .padding(.top, 8)
        } label: {
            HStack(spacing: 7) {
                Image(systemName: "slider.horizontal.3")
                    .font(.system(size: 10, weight: .semibold))
                    .foregroundStyle(.secondary)
                Text("Advanced SSH settings")
                    .font(.system(size: 12, weight: .semibold))
                Spacer()
                Text("keys, jump hosts, keepalive, raw options")
                    .font(.system(size: 10))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            .padding(.vertical, 2)
        }
        .padding(10)
        .background(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .fill(Color.secondary.opacity(0.045))
        )
    }

    private func defaultForwardDraft() -> TunnelDraft.ForwardDraft {
        TunnelDraft.ForwardDraft(
            kind: .local,
            listenPort: nextDraftListenPort,
            destinationHost: suggestions.destinationHosts.first ?? "localhost",
            destinationPort: suggestions.destinationPorts.first ?? "3000"
        )
    }

    private var nextDraftListenPort: String {
        let used = Set(draft.forwards.compactMap { Int($0.listenPort) })
        var candidate = suggestions.nextAvailableLocalPort
        while used.contains(candidate) {
            candidate += 1
        }
        return String(candidate)
    }

    private func applyEndpointGuess(overwrite: Bool) {
        let host = draft.host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !host.isEmpty else { return }

        if let port = suggestions.preferredSSHPort(for: host), overwrite || draft.sshPort.isEmpty || draft.sshPort == "22" {
            draft.sshPort = port
        }

        if let user = suggestions.preferredUser(for: host, sshPort: draft.sshPort), overwrite || draft.user.isEmpty {
            draft.user = user
        }

        if let identity = suggestions.preferredIdentity(for: host, user: draft.user), overwrite || draft.identityFile.isEmpty {
            draft.identityFile = identity
        }

        if let jumpHost = suggestions.preferredJumpHost(for: host), overwrite || draft.jumpHost.isEmpty {
            draft.jumpHost = jumpHost
        }
    }

    private func compactTextField(_ placeholder: String, text: Binding<String>, width: CGFloat) -> some View {
        TextField(placeholder, text: text)
            .textFieldStyle(.roundedBorder)
            .frame(width: width)
    }

    private func editorLabel(_ text: String) -> some View {
        Text(text)
            .font(.system(size: 10.5, weight: .semibold))
            .foregroundStyle(.secondary)
            .frame(width: 70, alignment: .trailing)
    }
}

private struct EditorSection<Content: View>: View {
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
                .stroke(Color.black.opacity(0.035), lineWidth: 1)
        )
    }
}

private struct ForwardEditorCard: View {
    @Binding var forward: TunnelDraft.ForwardDraft
    let suggestions: TunnelEditorSuggestions
    let canRemove: Bool
    let onRemove: () -> Void
    @State private var isAdvancedExpanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Label(forwardTitle, systemImage: "arrow.left.and.right")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(.secondary)
                Spacer()
                if canRemove {
                    Button("Remove", role: .destructive, action: onRemove)
                        .buttonStyle(.bordered)
                        .controlSize(.small)
                }
            }

            routeFields

            DisclosureGroup(isExpanded: $isAdvancedExpanded) {
                Grid(alignment: .leading, horizontalSpacing: 10, verticalSpacing: 8) {
                    GridRow {
                        editorLabel("Type")
                        Picker("Type", selection: $forward.kind) {
                            Text("Local").tag(ForwardSpec.Kind.local)
                            Text("Remote").tag(ForwardSpec.Kind.remote)
                            Text("Dynamic").tag(ForwardSpec.Kind.dynamic)
                        }
                        .labelsHidden()
                        .pickerStyle(.segmented)
                        .frame(maxWidth: 220)
                    }
                    GridRow {
                        editorLabel("Bind")
                        SuggestingTextField(
                            placeholder: "localhost",
                            text: $forward.bindAddress,
                            suggestions: suggestions.bindAddresses
                        )
                    }
                }
                .padding(.top, 6)
            } label: {
                Text("Advanced route settings")
                    .font(.system(size: 10.5, weight: .semibold))
                    .foregroundStyle(.secondary)
            }
        }
        .padding(9)
        .background(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .fill(Color.secondary.opacity(0.045))
        )
    }

    @ViewBuilder
    private var routeFields: some View {
        Grid(alignment: .leading, horizontalSpacing: 10, verticalSpacing: 8) {
            switch forward.kind {
            case .local:
                GridRow {
                    editorLabel("Local Port")
                    SuggestingTextField(
                        placeholder: "8875",
                        text: $forward.listenPort,
                        suggestions: []
                    )
                    .frame(width: 92)
                }
                GridRow {
                    editorLabel("To")
                    destinationFields
                }
            case .remote:
                GridRow {
                    editorLabel("Remote Port")
                    SuggestingTextField(
                        placeholder: "8875",
                        text: $forward.listenPort,
                        suggestions: []
                    )
                    .frame(width: 92)
                }
                GridRow {
                    editorLabel("From")
                    destinationFields
                }
            case .dynamic:
                GridRow {
                    editorLabel("SOCKS Port")
                    SuggestingTextField(
                        placeholder: "1080",
                        text: $forward.listenPort,
                        suggestions: []
                    )
                    .frame(width: 92)
                }
            }
        }
    }

    private var destinationFields: some View {
        HStack(spacing: 6) {
            SuggestingTextField(
                placeholder: "localhost",
                text: $forward.destinationHost,
                suggestions: suggestions.destinationHosts
            )
            Text(":")
                .font(.system(size: 12, weight: .semibold, design: .monospaced))
                .foregroundStyle(.secondary)
            SuggestingTextField(
                placeholder: "3000",
                text: $forward.destinationPort,
                suggestions: suggestions.destinationPorts
            )
            .frame(width: 76)
        }
    }

    private var forwardTitle: String {
        switch forward.kind {
        case .local:
            return "Local forward"
        case .remote:
            return "Remote forward"
        case .dynamic:
            return "Dynamic SOCKS forward"
        }
    }

    private func editorLabel(_ text: String) -> some View {
        Text(text)
            .font(.system(size: 10.5, weight: .semibold))
            .foregroundStyle(.secondary)
            .frame(width: 70, alignment: .trailing)
    }
}

private struct SuggestingTextField: NSViewRepresentable {
    let placeholder: String
    @Binding var text: String
    let suggestions: [String]

    func makeNSView(context: Context) -> NSComboBox {
        let comboBox = NSComboBox()
        comboBox.isEditable = true
        comboBox.completes = true
        comboBox.usesDataSource = false
        comboBox.numberOfVisibleItems = 8
        comboBox.placeholderString = placeholder
        comboBox.controlSize = .small
        comboBox.font = .systemFont(ofSize: NSFont.systemFontSize(for: .small))
        comboBox.delegate = context.coordinator
        comboBox.target = context.coordinator
        comboBox.action = #selector(Coordinator.commit(_:))
        comboBox.addItems(withObjectValues: suggestions)
        return comboBox
    }

    func updateNSView(_ comboBox: NSComboBox, context: Context) {
        context.coordinator.parent = self

        if comboBox.stringValue != text {
            comboBox.stringValue = text
        }

        let existing = (0..<comboBox.numberOfItems).compactMap { comboBox.itemObjectValue(at: $0) as? String }
        if existing != suggestions {
            comboBox.removeAllItems()
            comboBox.addItems(withObjectValues: suggestions)
            comboBox.numberOfVisibleItems = max(4, min(10, max(suggestions.count, 1)))
        }
    }

    func makeCoordinator() -> Coordinator {
        Coordinator(parent: self)
    }

    final class Coordinator: NSObject, NSComboBoxDelegate, NSControlTextEditingDelegate {
        var parent: SuggestingTextField

        init(parent: SuggestingTextField) {
            self.parent = parent
        }

        func controlTextDidChange(_ obj: Notification) {
            guard let comboBox = obj.object as? NSComboBox else { return }
            parent.text = comboBox.stringValue
        }

        func comboBoxSelectionDidChange(_ notification: Notification) {
            guard let comboBox = notification.object as? NSComboBox else { return }
            parent.text = comboBox.stringValue
        }

        @MainActor
        @objc func commit(_ sender: NSComboBox) {
            parent.text = sender.stringValue
        }
    }
}

struct DraftError: LocalizedError {
    let message: String

    init(_ message: String) {
        self.message = message
    }

    var errorDescription: String? { message }
}

private extension String {
    var nonEmptyValue: String? {
        let trimmed = trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }
}

private extension Notification.Name {
    static let portKeeperDidFinishLaunching = Notification.Name("BurrowDidFinishLaunching")
}
