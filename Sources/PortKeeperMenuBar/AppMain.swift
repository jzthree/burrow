import AppKit
import Combine
import PortKeeperCore
import SwiftUI

@main
struct BurrowApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @StateObject private var viewModel = MenuBarViewModel()

    var body: some Scene {
        MenuBarExtra {
            MenuBarContent(viewModel: viewModel)
                .frame(width: 400, height: 520)
        } label: {
            Label(viewModel.menuBarTitle, systemImage: viewModel.menuBarSymbol)
        }
        .menuBarExtraStyle(.window)
    }
}

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
        NotificationCenter.default.addObserver(
            forName: .portKeeperDidFinishLaunching,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor [weak self] in
                self?.startEnabledTunnelsIfNeeded()
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
        tunnels.contains(where: \.isRunning) ? "lock.shield.fill" : "lock.shield"
    }

    func loadConfig() {
        do {
            let config = try store.load()
            let running = Set(tasks.keys)
            let existingStatesByName = Dictionary(uniqueKeysWithValues: tunnels.map { ($0.id, $0) })
            tunnels = config.tunnels.map { tunnel in
                let existingState = existingStatesByName[tunnel.name]
                return TunnelState(
                    id: tunnel.name,
                    tunnel: tunnel,
                    isConfiguredEnabled: tunnel.enabled,
                    isRunning: running.contains(tunnel.name),
                    connectionState: running.contains(tunnel.name) ? .connecting : .disconnected,
                    lastMessage: existingState?.lastMessage ?? (running.contains(tunnel.name) ? "Connecting" : (tunnel.enabled ? "Auto-connect enabled" : "Auto-connect disabled")),
                    recentLogs: existingState?.recentLogs ?? []
                )
            }
            .sorted { $0.tunnel.name < $1.tunnel.name }

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

    func reloadConfig() {
        stopMissingTunnels()
        loadConfig()
    }

    func startEnabledTunnels() {
        for tunnel in tunnels where tunnel.isConfiguredEnabled {
            startTunnel(named: tunnel.id)
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

    func startTunnel(named name: String) {
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
            preparation = try connectionPreparation(for: launchTunnel)
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
        let task = Task {
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
        editorDraft = TunnelDraft.newTunnel()
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
                _ = try store.remove(name: originalName)
                if tasks[originalName] != nil {
                    stopTunnel(named: originalName)
                }
            }

            try store.upsert(tunnel)
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

    private func connectionPreparation(for tunnel: TunnelConfig) throws -> ConnectionPreparation {
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
            case .exited(let code):
                self.owner?.updateState(for: self.tunnelName, isRunning: false, state: .failed, message: "Disconnected (exit \(code))")
                self.owner?.globalMessage = "\(self.tunnelName): ssh exited with code \(code)."
            case .failedToStart(let message):
                self.owner?.updateState(for: self.tunnelName, isRunning: false, state: .failed, message: "Connect failed: \(message)")
                self.owner?.globalMessage = "\(self.tunnelName): \(message)"
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

    struct EndpointGroup: Identifiable {
        let endpoint: String
        let tunnels: [MenuBarViewModel.TunnelState]

        var id: String { endpoint }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            header
            Divider()
            if let draft = viewModel.editorDraft {
                TunnelEditorSheet(
                    draft: binding(for: draft),
                    onCancel: { viewModel.closeEditor() },
                    onSave: { viewModel.saveEditor() },
                    onDelete: { viewModel.deleteEditorTunnel() }
                )
            } else {
                if viewModel.tunnels.isEmpty {
                    emptyState
                } else {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 12) {
                            ForEach(endpointGroups) { group in
                                VStack(alignment: .leading, spacing: 6) {
                                    EndpointHeader(group: group)

                                    VStack(alignment: .leading, spacing: 8) {
                                        ForEach(group.tunnels) { tunnel in
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
                                }
                            }
                        }
                        .padding(.vertical, 2)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
                }
                Divider()
                footer
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(Color(nsColor: .windowBackgroundColor))
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                if viewModel.editorDraft != nil {
                    Button("Back") {
                        viewModel.closeEditor()
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                } else {
                    Text("Burrow")
                        .font(.system(size: 15, weight: .semibold))
                }
                Spacer()
                if viewModel.editorDraft == nil {
                    HealthSummaryPill(tunnels: viewModel.tunnels)
                } else {
                    HeaderPill(text: "Editing tunnel")
                }
            }
            Text(viewModel.globalMessage)
                .font(.system(size: 11))
                .foregroundStyle(.secondary)
        }
    }

    private var emptyState: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("No tunnels saved.")
                .font(.system(size: 13, weight: .medium))
            Text("Create tunnels with the CLI or edit the central config, then reload here.")
                .font(.system(size: 11))
                .foregroundStyle(.secondary)
        }
    }

    private var footer: some View {
        VStack(alignment: .leading, spacing: 8) {
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
        Dictionary(grouping: viewModel.tunnels) { tunnel in
            "\(tunnel.tunnel.host):\(String(tunnel.tunnel.sshPort))"
        }
        .map { endpoint, tunnels in
            EndpointGroup(endpoint: endpoint, tunnels: tunnels.sorted { $0.tunnel.name < $1.tunnel.name })
        }
        .sorted { $0.endpoint.localizedStandardCompare($1.endpoint) == .orderedAscending }
    }
}

private struct EndpointHeader: View {
    let group: MenuBarContent.EndpointGroup

    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: "network")
                .font(.system(size: 9, weight: .semibold))
                .foregroundStyle(.secondary)
            Text(verbatim: group.endpoint)
                .font(.system(size: 10, weight: .semibold, design: .monospaced))
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .truncationMode(.middle)
            Spacer(minLength: 4)
            Text("\(group.tunnels.count)")
                .font(.system(size: 9, weight: .semibold))
                .foregroundStyle(.tertiary)
        }
        .padding(.horizontal, 2)
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
        HStack(spacing: 7) {
            summaryText(count: upCount, label: "up", color: .green)
            summaryText(count: connectingCount, label: "starting", color: .orange)
            summaryText(count: failedCount, label: "failed", color: .red)
            summaryText(count: waitingCount, label: "waiting", color: .gray)
        }
        .padding(.horizontal, 9)
        .padding(.vertical, 5)
        .background(
            Capsule(style: .continuous)
                .fill(Color(nsColor: .controlBackgroundColor))
        )
        .help("\(tunnels.count) configured")
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

    private func summaryText(count: Int, label: String, color: Color) -> some View {
        HStack(spacing: 3) {
            Circle()
                .fill(color)
                .frame(width: 5, height: 5)
            Text("\(count) \(label)")
                .font(.system(size: 10.5, weight: .semibold))
                .foregroundStyle(.secondary)
        }
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
    @State private var isDetailsPresented = false

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .top, spacing: 8) {
                Circle()
                    .fill(statusColor)
                    .frame(width: 9, height: 9)
                    .padding(.top, 4)

                VStack(alignment: .leading, spacing: 6) {
                    HStack(alignment: .firstTextBaseline, spacing: 8) {
                        Text(tunnel.tunnel.name)
                            .font(.system(size: 13, weight: .semibold))
                            .lineLimit(1)
                            .truncationMode(.middle)
                            .layoutPriority(1)

                        Spacer(minLength: 6)

                        HStack(spacing: 5) {
                            Text("Auto")
                                .font(.system(size: 9.5, weight: .medium))
                                .foregroundStyle(.secondary)
                            Toggle("", isOn: Binding(
                                get: { tunnel.isConfiguredEnabled },
                                set: { value in
                                    onToggleAutoConnect(value)
                                }
                            ))
                            .labelsHidden()
                            .toggleStyle(.switch)
                            .controlSize(.mini)
                        }
                        failureInfoSlot
                        rowMenu
                    }

                    HStack(alignment: .center, spacing: 8) {
                        routeSummaryView

                        Spacer(minLength: 6)

                        primaryActionButton
                    }
                }
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 9)
        .background(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .fill(Color(nsColor: .controlBackgroundColor))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .stroke(Color.black.opacity(0.04), lineWidth: 1)
        )
        .overlay(alignment: .topTrailing) {
            if let presentation = failurePresentation, isFailureTooltipVisible {
                failureTooltip(presentation)
                    .offset(x: -38, y: -10)
                    .allowsHitTesting(false)
            }
        }
        .zIndex(isFailureTooltipVisible ? 2 : 0)
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

    @ViewBuilder
    private var routeSummaryView: some View {
        if tunnel.tunnel.forwards.count == 1, let forward = tunnel.tunnel.forwards.first {
            routeView(for: forward)
                .help(fullRouteText(for: forward))
        } else {
            Text(verbatim: compactRouteSummary)
                .font(.system(size: 10.8, weight: .medium))
                .monospacedDigit()
                .foregroundStyle(.primary.opacity(0.82))
                .lineLimit(1)
                .truncationMode(.tail)
                .help(fullRouteSummary)
        }
    }

    @ViewBuilder
    private func routeView(for forward: ForwardSpec) -> some View {
        switch forward.kind {
        case .local:
            HStack(spacing: 4) {
                Text(verbatim: String(forward.listenPort))
                Image(systemName: "arrow.right")
                    .font(.system(size: 9, weight: .bold))
                    .foregroundStyle(.secondary)
                Text(verbatim: compactDestinationText(for: forward))
                Image(systemName: "globe")
                    .font(.system(size: 10))
                    .foregroundStyle(.secondary)
                Text(verbatim: endpointText)
            }
            .font(.system(size: 10.8, weight: .medium))
            .monospacedDigit()
            .foregroundStyle(.primary.opacity(0.82))
            .lineLimit(1)
            .truncationMode(.tail)
        case .remote:
            HStack(spacing: 4) {
                Text(verbatim: compactDestinationText(for: forward))
                Image(systemName: "arrow.left")
                    .font(.system(size: 9, weight: .bold))
                    .foregroundStyle(.secondary)
                Text(verbatim: String(forward.listenPort))
                Image(systemName: "globe")
                    .font(.system(size: 10))
                    .foregroundStyle(.secondary)
                Text(verbatim: endpointText)
            }
            .font(.system(size: 10.8, weight: .medium))
            .monospacedDigit()
            .foregroundStyle(.primary.opacity(0.82))
            .lineLimit(1)
            .truncationMode(.tail)
        case .dynamic:
            HStack(spacing: 4) {
                Text(verbatim: "SOCKS")
                Text(verbatim: String(forward.listenPort))
                Image(systemName: "globe")
                    .font(.system(size: 10))
                    .foregroundStyle(.secondary)
                Text(verbatim: endpointText)
            }
            .font(.system(size: 10.8, weight: .medium))
            .monospacedDigit()
            .foregroundStyle(.primary.opacity(0.82))
            .lineLimit(1)
            .truncationMode(.tail)
        }
    }

    private var compactRouteSummary: String {
        tunnel.tunnel.forwards.map { forward in
            switch forward.kind {
            case .local:
                return "\(String(forward.listenPort)) -> \(compactDestinationText(for: forward)) @ \(endpointText)"
            case .remote:
                return "\(compactDestinationText(for: forward)) <- \(String(forward.listenPort)) @ \(endpointText)"
            case .dynamic:
                return "SOCKS \(String(forward.listenPort)) @ \(endpointText)"
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
            Image(systemName: "ellipsis.circle")
                .font(.system(size: 14, weight: .semibold))
                .foregroundStyle(.secondary)
        }
        .menuStyle(.borderlessButton)
        .menuIndicator(.hidden)
        .frame(width: 22, alignment: .trailing)
        .popover(isPresented: $isDetailsPresented, arrowEdge: .trailing) {
            TunnelDetailsPopover(
                tunnel: tunnel,
                routeSummary: fullRouteSummary,
                commandText: sshCommandText,
                failurePresentation: failurePresentation
            )
        }
    }

    @ViewBuilder
    private var primaryActionButton: some View {
        Button(tunnel.isRunning ? "Stop" : "Connect") {
            if tunnel.isRunning {
                onStop()
            } else {
                onStart()
            }
        }
        .buttonStyle(.borderedProminent)
        .tint(tunnel.isRunning ? .red : .accentColor)
        .controlSize(.small)
        .frame(width: 82, alignment: .trailing)
    }

    private var failureInfoSlot: some View {
        Group {
            if failurePresentation != nil {
                Image(systemName: "info.circle.fill")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(Color(red: 0.68, green: 0.12, blue: 0.10))
            } else {
                Color.clear
            }
        }
        .frame(width: 14, height: 14)
        .contentShape(Rectangle())
        .onHover { hovering in
            guard failurePresentation != nil else {
                isFailureTooltipVisible = false
                return
            }
            withAnimation(.easeInOut(duration: 0.08)) {
                isFailureTooltipVisible = hovering
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

        if containsAny(lowercased, ["operation timed out", "connection timed out", "network is unreachable", "no route to host", "connection refused"]) {
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

    static func newTunnel() -> TunnelDraft {
        TunnelDraft(
            tunnel: TunnelConfig(
                name: "",
                host: "",
                forwards: [
                    ForwardSpec(kind: .local, listenPort: 0, destinationHost: "", destinationPort: 0),
                ],
                enabled: true
            ),
            originalName: nil
        )
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
    let onCancel: () -> Void
    let onSave: () -> Void
    let onDelete: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text(draft.originalName == nil ? "New Tunnel" : "Edit Tunnel")
                    .font(.system(size: 16, weight: .semibold))
                Spacer()
                Toggle("Auto-connect", isOn: $draft.enabled)
                    .toggleStyle(.switch)
                    .controlSize(.small)
            }

            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    detailsSection
                    timingSection
                    forwardsSection
                    sshOptionsSection
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
    }

    private var detailsSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Connection")
                .font(.system(size: 13, weight: .medium))
            Grid(alignment: .leading, horizontalSpacing: 10, verticalSpacing: 8) {
                GridRow {
                    Text("Name")
                    TextField("prod-db", text: $draft.name)
                }
                GridRow {
                    Text("Host")
                    TextField("bastion.example.com", text: $draft.host)
                }
                GridRow {
                    Text("User")
                    TextField("alice", text: $draft.user)
                }
                GridRow {
                    Text("SSH Port")
                    TextField("22", text: $draft.sshPort)
                }
                GridRow {
                    Text("Identity")
                    TextField("~/.ssh/id_ed25519", text: $draft.identityFile)
                }
                GridRow {
                    Text("Jump Host")
                    TextField("jumper.example.com", text: $draft.jumpHost)
                }
            }
            .textFieldStyle(.roundedBorder)
        }
    }

    private var timingSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Keepalive")
                .font(.system(size: 13, weight: .medium))
            Grid(alignment: .leading, horizontalSpacing: 10, verticalSpacing: 8) {
                GridRow {
                    Text("Alive Interval")
                    TextField("30", text: $draft.serverAliveInterval)
                }
                GridRow {
                    Text("Alive Count Max")
                    TextField("5", text: $draft.serverAliveCountMax)
                }
                GridRow {
                    Text("Reconnect Delay")
                    TextField("5", text: $draft.reconnectDelaySeconds)
                }
            }
            .textFieldStyle(.roundedBorder)
        }
    }

    private var forwardsSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Forwards")
                    .font(.system(size: 13, weight: .medium))
                Spacer()
                Button("Add Forward") {
                    draft.forwards.append(TunnelDraft.ForwardDraft())
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
            }

            ForEach($draft.forwards) { $forward in
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Picker("Type", selection: $forward.kind) {
                            Text("Local").tag(ForwardSpec.Kind.local)
                            Text("Remote").tag(ForwardSpec.Kind.remote)
                            Text("Dynamic").tag(ForwardSpec.Kind.dynamic)
                        }
                        .pickerStyle(.segmented)

                        Button("Remove", role: .destructive) {
                            draft.forwards.removeAll { $0.id == forward.id }
                        }
                        .buttonStyle(.bordered)
                        .controlSize(.small)
                    }

                    Grid(alignment: .leading, horizontalSpacing: 10, verticalSpacing: 8) {
                        GridRow {
                            Text("Bind")
                            TextField("localhost", text: $forward.bindAddress)
                        }
                        GridRow {
                            Text("Listen Port")
                            TextField("8875", text: $forward.listenPort)
                        }
                        if forward.kind != .dynamic {
                            GridRow {
                                Text("Dest Host")
                                TextField("localhost", text: $forward.destinationHost)
                            }
                            GridRow {
                                Text("Dest Port")
                                TextField("3000", text: $forward.destinationPort)
                            }
                        }
                    }
                    .textFieldStyle(.roundedBorder)
                }
                .padding(10)
                .background(
                    RoundedRectangle(cornerRadius: 10, style: .continuous)
                        .fill(Color(nsColor: .controlBackgroundColor))
                )
            }
        }
    }

    private var sshOptionsSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Extra SSH Options")
                .font(.system(size: 13, weight: .medium))
            Text("One `key=value` or raw ssh `-o` value per line.")
                .font(.system(size: 11))
                .foregroundStyle(.secondary)
            TextEditor(text: $draft.extraSSHOptionsText)
                .font(.system(size: 12, design: .monospaced))
                .frame(minHeight: 120)
                .overlay(
                    RoundedRectangle(cornerRadius: 8)
                        .stroke(Color.secondary.opacity(0.2))
                )
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
