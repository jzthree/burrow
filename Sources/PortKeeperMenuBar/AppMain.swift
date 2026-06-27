import AppKit
import Combine
import PortKeeperCore
import ServiceManagement
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
        Label {
            Text(viewModel.menuBarTitle)
        } icon: {
            Image(nsImage: viewModel.isAnyTunnelRunning ? MenuBarIcon.active : MenuBarIcon.idle)
        }
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
        var retryAttempt: Int = 0
        var nextRetryAt: Date? = nil
        var failedAt: Date? = nil
        var serviceReachable: ForwardProbe.Result = .unknown
    }

    struct GatewayState: Identifiable {
        let id: String
        let config: GatewayConfig
        var isRunning: Bool
        var connectionState: ConnectionState
        var lastMessage: String
        var recentLogs: [String]
    }

    private struct PreparedTunnelLaunch {
        let name: String
        let tunnel: TunnelConfig
        /// Same tunnel without the gateway's SOCKS ProxyCommand, used when the
        /// target is reachable over a system VPN and Burrow shouldn't start its
        /// own (conflicting) openconnect.
        let directTunnel: TunnelConfig
        let preparation: ConnectionPreparation
    }

    let store = ConfigStore()
    let passwordStore = PasswordStore()

    @Published private(set) var tunnels: [TunnelState] = []
    @Published private(set) var gateways: [GatewayState] = []
    @Published var globalMessage = ""
    @Published var editorDraft: TunnelDraft? {
        didSet {
            let draftChanged = oldValue?.id != editorDraft?.id
            if draftChanged || (oldValue != nil) != (editorDraft != nil) {
                syncEditorWindow()
            }
        }
    }
    @Published var gatewayDraft: GatewayDraft? {
        didSet {
            let draftChanged = oldValue?.id != gatewayDraft?.id
            if draftChanged || (oldValue != nil) != (gatewayDraft != nil) {
                syncEditorWindow()
            }
        }
    }
    @Published var profileDraft: ProfileDraft? {
        didSet {
            let draftChanged = oldValue?.id != profileDraft?.id
            if draftChanged || (oldValue != nil) != (profileDraft != nil) {
                syncEditorWindow()
            }
        }
    }
    @Published var importCandidates: [SSHConfigImportCandidate]?
    @Published private(set) var launchAtLoginEnabled = false
    @Published private(set) var terminalApp = "auto"
    @Published private(set) var twoFactorUnlockCacheSeconds = 0
    /// When true, an intentional Quit leaves the VPN and tunnels running and
    /// the app re-adopts them on next launch. When false (default), Quit tears
    /// everything down. A crash/kill always leaves them running regardless.
    @Published var keepRunningAfterQuit: Bool {
        didSet {
            UserDefaults.standard.set(keepRunningAfterQuit, forKey: Self.keepRunningKey)
        }
    }
    private static let keepRunningKey = "keepRunningAfterQuit"
    /// Section IDs the user has flipped from their default open/closed state.
    /// Stored inverted so each section keeps a sensible default (tunnel groups
    /// open, the SSH Hosts list closed) without seeding.
    @Published var toggledSections: Set<String> {
        didSet {
            UserDefaults.standard.set(Array(toggledSections), forKey: Self.toggledSectionsKey)
        }
    }
    private static let toggledSectionsKey = "toggledSections"

    func isSectionExpanded(_ id: String, defaultExpanded: Bool) -> Bool {
        toggledSections.contains(id) ? !defaultExpanded : defaultExpanded
    }

    func toggleSection(_ id: String) {
        if toggledSections.contains(id) {
            toggledSections.remove(id)
        } else {
            toggledSections.insert(id)
        }
    }

    @Published private(set) var sshConfigHosts: [SSHConfigHost] = []

    private let notifier = BurrowNotifier()
    private var serviceProbeTask: Task<Void, Never>?
    private var editorWindowController: EditorWindowController?
    private var configWatcher: ConfigFileWatcher?
    private var tasks: [String: Task<Void, Never>] = [:]
    private var gatewayTasks: [String: Task<Void, Never>] = [:]
    private var pendingGatewayCredentialSaves: [String: PendingCredentialSave] = [:]
    private var invalidGatewayCredentialKeys: Set<TunnelCredentialKey> = []
    /// In-flight browser sign-ins by gateway name; presence blocks duplicate
    /// sign-in windows.
    private var activeSAMLAuthenticators: [String: any SAMLAuthenticating] = [:]
    /// Gateways whose VPN session survived an app restart and was adopted:
    /// the processes are alive but no supervisor task owns them, so stop and
    /// health checks go through process/port matching instead.
    private var adoptedGateways: Set<String> = []
    /// Consecutive through-tunnel health-probe failures per gateway; a session
    /// is only declared dead after a couple in a row so a transient blip
    /// doesn't tear down a working VPN.
    private var gatewayHealthFailures: [String: Int] = [:]
    private var gatewayHealthTick = 0
    private var toolInstallWatchTask: Task<Void, Never>?
    private var samlSessionConnectedAt: [String: Date] = [:]
    private var samlReauthAttempts: [String: Int] = [:]
    private var hasStartedAutoConnect = false
    private var pendingCredentialSaves: [String: PendingCredentialSave] = [:]
    private var activeCredentialSources: [String: CredentialSource] = [:]
    private var sawAuthenticationFailure: Set<String> = []
    private var sessionPasswords: [TunnelCredentialKey: String] = [:]
    private var sessionPasswordsByHostUser: [HostUserKey: String] = [:]
    private var savedCredentialKeysThisSession: Set<TunnelCredentialKey> = []
    private var invalidCredentialKeys: Set<TunnelCredentialKey> = []
    private var authRePromptCounts: [String: Int] = [:]
    private var tunnelPromptAllowed: [String: Bool] = [:]

    init() {
        keepRunningAfterQuit = UserDefaults.standard.bool(forKey: Self.keepRunningKey)
        toggledSections = Set(UserDefaults.standard.stringArray(forKey: Self.toggledSectionsKey) ?? [])
        loadConfig()
        adoptSurvivingGatewaySessions()
        sshConfigHosts = SSHConfigParser.parse()
        refreshLaunchAtLoginState()
        startConfigWatcher()
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
            // willTerminate fires only on a clean exit (Quit, ⌘Q, logout) — not
            // on a crash/SIGKILL — so this is exactly "intentional close".
            MainActor.assumeIsolated {
                self?.performShutdownTeardown()
            }
        }
        NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.didWakeNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor [weak self] in
                self?.handleWakeFromSleep()
            }
        }
        startServiceProbeLoop()
    }

    /// Sleep silently kills tunnel TCP sessions and VPN gateways; ssh keepalive
    /// only notices after its timeout. On wake, give the network a moment to
    /// return, then restart what should be running so it reconnects promptly.
    private func handleWakeFromSleep() {
        globalMessage = "Woke from sleep — reconnecting."
        Task { @MainActor [weak self] in
            try? await Task.sleep(for: .seconds(3))
            guard let self else { return }
            for state in self.gateways where state.isRunning || state.connectionState == .connected {
                // Sleep commonly kills the VPN session while ocproxy keeps
                // holding the port, so prefer a real through-tunnel probe; fall
                // back to the port check when no healthCheckHost is set.
                let dead: Bool
                if let target = state.config.healthCheckTarget {
                    let port = state.config.socksPort
                    dead = !(await Task.detached {
                        SOCKSProbe.canReach(proxyPort: port, targetHost: target.host, targetPort: target.port, timeout: 6)
                    }.value)
                } else {
                    dead = !PortProbe.canConnect(host: "127.0.0.1", port: state.config.socksPort)
                }
                if dead {
                    self.gatewayHealthFailures[state.id] = 0
                    self.stopGateway(named: state.id)
                    self.updateGatewayState(for: state.id, isRunning: false, state: .disconnected, message: "VPN dropped on sleep — reconnect")
                }
            }
            for state in self.tunnels where self.tasks[state.id] != nil {
                self.restartTunnel(named: state.id)
            }
        }
    }

    /// Periodically checks whether the remote service behind each connected
    /// tunnel is actually accepting connections (vs. just "ssh owns the port").
    private func startServiceProbeLoop() {
        serviceProbeTask?.cancel()
        serviceProbeTask = Task { @MainActor [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(10))
                guard let self, !Task.isCancelled else { return }
                await self.probeConnectedServices()
            }
        }
    }

    /// A previous run's openconnect + ocproxy can outlive the app (quit with
    /// "keep running", or an update relaunch). Adopt such sessions at startup
    /// so a working VPN shows as connected instead of orphaned.
    private func adoptSurvivingGatewaySessions() {
        for state in gateways where gatewayTasks[state.id] == nil && !state.isRunning {
            guard GatewayPortReclaimer.hasLiveSession(socksPort: state.config.socksPort, server: state.config.server) else {
                continue
            }
            adoptedGateways.insert(state.id)
            updateGatewayState(for: state.id, isRunning: true, state: .connected, message: "Adopted running VPN session")
            markGatewayConnected(named: state.id)
        }
    }

    private func probeConnectedServices() async {
        // Adopted gateways have no supervisor watching them; notice here when
        // their session ends so the menu doesn't show a dead VPN as connected.
        // openconnect can exit while its ocproxy child lingers holding the
        // SOCKS port — that orphan answers a plain port check but routes
        // nowhere, so liveness must confirm openconnect itself is alive.
        let adopted = Array(adoptedGateways).compactMap { name in
            gateways.first(where: { $0.id == name }).map { (name: name, config: $0.config) }
        }
        if !adopted.isEmpty {
            let dead = await Task.detached { () -> [String] in
                adopted.filter { !GatewayPortReclaimer.hasLiveSession(socksPort: $0.config.socksPort, server: $0.config.server) }
                    .map(\.name)
            }.value
            for name in dead {
                adoptedGateways.remove(name)
                if let config = gateways.first(where: { $0.id == name })?.config {
                    // Reap the orphaned ocproxy so the stale port stops
                    // masquerading as a working tunnel.
                    GatewayPortReclaimer.reclaimStaleListeners(port: config.socksPort)
                }
                updateGatewayState(for: name, isRunning: false, state: .disconnected, message: "VPN session ended — reconnect")
            }
        }

        await probeGatewayHealth()

        let targets: [(name: String, host: String, port: Int)] = tunnels.compactMap { state in
            guard state.connectionState == .connected,
                  let forward = state.tunnel.forwards.first(where: { $0.kind != .remote }) else {
                return nil
            }
            let host = forward.bindAddress.flatMap { $0.isEmpty ? nil : $0 } ?? "127.0.0.1"
            return (state.id, host, forward.listenPort)
        }
        guard !targets.isEmpty else { return }

        let results = await Task.detached { () -> [String: ForwardProbe.Result] in
            var out: [String: ForwardProbe.Result] = [:]
            for target in targets {
                out[target.name] = ForwardProbe.probe(host: target.host, port: target.port)
            }
            return out
        }.value

        for (name, result) in results {
            if let index = tunnels.firstIndex(where: { $0.id == name }), tunnels[index].connectionState == .connected {
                tunnels[index].serviceReachable = result
            }
        }
    }

    /// For gateways that declare a healthCheckHost, probe THROUGH the SOCKS
    /// proxy to a host only reachable when the VPN is genuinely up. A stale
    /// ocproxy (session died on sleep/network change but the process lingers)
    /// keeps the port open and passes every process/port check, yet routes
    /// nowhere — this is the only thing that catches it. Runs ~every 30s.
    private func probeGatewayHealth() async {
        gatewayHealthTick += 1
        guard gatewayHealthTick % 3 == 0 else { return }

        let checks: [(name: String, port: Int, host: String, target: Int)] = gateways.compactMap { state in
            guard state.connectionState == .connected,
                  let target = state.config.healthCheckTarget else {
                return nil
            }
            return (state.id, state.config.socksPort, target.host, target.port)
        }
        guard !checks.isEmpty else { return }

        let reachability = await Task.detached { () -> [String: Bool] in
            var out: [String: Bool] = [:]
            for check in checks {
                out[check.name] = SOCKSProbe.canReach(
                    proxyPort: check.port,
                    targetHost: check.host,
                    targetPort: check.target,
                    timeout: 6
                )
            }
            return out
        }.value

        for (name, reachable) in reachability {
            guard gateways.contains(where: { $0.id == name && $0.connectionState == .connected }) else {
                gatewayHealthFailures[name] = 0
                continue
            }
            if reachable {
                gatewayHealthFailures[name] = 0
                continue
            }
            let failures = gatewayHealthFailures[name, default: 0] + 1
            gatewayHealthFailures[name] = failures
            // Two strikes (~1 min) before declaring the tunnel dead.
            if failures >= 2 {
                gatewayHealthFailures[name] = 0
                stopGateway(named: name)
                updateGatewayState(for: name, isRunning: false, state: .disconnected, message: "VPN unreachable — reconnect")
                globalMessage = "Gateway \(name) stopped passing traffic; marked disconnected."
            }
        }
    }

    /// Synchronously tears down tunnels and VPN gateways on an intentional
    /// quit (unless the user opted to keep them running). Must be synchronous:
    /// child ssh/openconnect processes survive the parent otherwise, and async
    /// cleanup wouldn't finish before the app exits.
    private func performShutdownTeardown() {
        guard !keepRunningAfterQuit else {
            return
        }

        // Cancelling a supervisor task runs its cancellation handler, which
        // SIGTERMs the launched process synchronously.
        for id in Array(tasks.keys) {
            tasks[id]?.cancel()
            tasks[id] = nil
        }
        for id in Array(gatewayTasks.keys) {
            gatewayTasks[id]?.cancel()
            gatewayTasks[id] = nil
        }

        guard let config = try? store.load() else {
            return
        }
        // Kill VPN processes for every configured gateway — this also catches
        // adopted/orphaned sessions that have no supervisor task to cancel.
        for gateway in config.gateways {
            GatewayPortReclaimer.killGatewayProcesses(socksPort: gateway.socksPort, server: gateway.server)
        }
        // Belt-and-suspenders for any ssh that outlived its SIGTERM.
        for tunnel in config.tunnels {
            if let prepared = try? preparedTunnelForLaunch(tunnel) {
                try? PortKeeperRuntimeRegistry.reclaimOwnedProcess(for: prepared)
            }
        }
    }

    deinit {
        for task in tasks.values {
            task.cancel()
        }
    }

    var menuBarTitle: String {
        let connectedCount = tunnels.filter { $0.connectionState == .connected }.count
        return connectedCount > 0 ? "Burrow \(connectedCount)" : "Burrow"
    }

    var isAnyTunnelRunning: Bool {
        tunnels.contains { $0.connectionState == .connected }
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
                    recentLogs: existingState?.recentLogs ?? [],
                    retryAttempt: isRunning ? (existingState?.retryAttempt ?? 0) : 0,
                    nextRetryAt: isRunning ? existingState?.nextRetryAt : nil,
                    failedAt: isRunning ? nil : existingState?.failedAt,
                    serviceReachable: isRunning ? (existingState?.serviceReachable ?? .unknown) : .unknown
                )
            }

            let runningGateways = Set(gatewayTasks.keys).union(adoptedGateways)
            let existingGatewaysByName = Dictionary(uniqueKeysWithValues: gateways.map { ($0.id, $0) })
            gateways = config.gateways.map { gateway in
                let existing = existingGatewaysByName[gateway.name]
                let isRunning = runningGateways.contains(gateway.name)
                return GatewayState(
                    id: gateway.name,
                    config: gateway,
                    isRunning: isRunning,
                    connectionState: isRunning
                        ? (existing?.connectionState ?? .connecting)
                        : (existing?.connectionState == .failed ? .failed : .disconnected),
                    lastMessage: existing?.lastMessage ?? (isRunning ? "Connecting" : "Not connected"),
                    recentLogs: existing?.recentLogs ?? []
                )
            }
            writeSSHInclude(for: config.gateways)
            profilesCache = config.profiles
            twoFactorAccounts = config.twoFactorAccounts
            terminalApp = normalizedTerminalApp(config.terminalApp)
            twoFactorUnlockCacheSeconds = normalizedTwoFactorUnlockCacheSeconds(config.twoFactorUnlockCacheSeconds)

            if tunnels.isEmpty {
                globalMessage = "No tunnels configured yet."
            } else {
                let runningCount = tunnels.filter(\.isRunning).count
                globalMessage = "Loaded \(tunnels.count) tunnel(s), \(runningCount) running."
            }
        } catch {
            tunnels = []
            gateways = []
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
        stopMissingGateways()
        loadConfig()
    }

    private func startConfigWatcher() {
        let watcher = ConfigFileWatcher(url: store.configURL) { [weak self] in
            self?.handleConfigFileChange()
        }
        configWatcher = watcher
        watcher.start()
    }

    private func handleConfigFileChange() {
        let previousMessage = globalMessage
        stopMissingTunnels()
        stopMissingGateways()
        loadConfig()
        // Keep action feedback (e.g. "Saved x.") instead of the generic load summary
        // when the watcher fires for our own writes.
        globalMessage = previousMessage
    }

    func startEnabledTunnels() {
        startTunnels(tunnels.filter(\.isConfiguredEnabled), allowPasswordPrompt: false, preloadCredentials: true)
    }

    func startEnabledTunnelsIfNeeded() {
        guard !hasStartedAutoConnect else {
            return
        }
        hasStartedAutoConnect = true
        startEnabledTunnels()
    }

    func startAll() {
        startTunnels(tunnels, allowPasswordPrompt: true, preloadCredentials: true)
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

        tunnelPromptAllowed[name] = allowPasswordPrompt
        guard let preparedLaunch = prepareTunnelLaunch(
            named: name,
            tunnel: tunnel,
            allowPasswordPrompt: allowPasswordPrompt,
            preloadedPasswords: nil
        ) else {
            return
        }

        launchWhenGatewayReady(preparedLaunch, allowGatewayPrompt: allowPasswordPrompt)
    }

    private func startTunnels(_ selectedTunnels: [TunnelState], allowPasswordPrompt: Bool, preloadCredentials: Bool) {
        var launchCandidates: [TunnelState] = []

        for tunnel in selectedTunnels {
            if tasks[tunnel.id] == nil {
                launchCandidates.append(tunnel)
            } else {
                updateState(for: tunnel.id, isRunning: true, message: "Already running")
            }
        }

        guard !launchCandidates.isEmpty else {
            return
        }

        let preloadedPasswords = preloadCredentials ? preloadPasswords(for: launchCandidates.map(\.tunnel)) : nil
        let preparedLaunches = launchCandidates.compactMap { tunnel -> PreparedTunnelLaunch? in
            tunnelPromptAllowed[tunnel.id] = allowPasswordPrompt
            return prepareTunnelLaunch(
                named: tunnel.id,
                tunnel: tunnel.tunnel,
                allowPasswordPrompt: allowPasswordPrompt,
                preloadedPasswords: preloadedPasswords
            )
        }

        for preparedLaunch in preparedLaunches {
            launchWhenGatewayReady(preparedLaunch, allowGatewayPrompt: allowPasswordPrompt)
        }
    }

    private func preloadPasswords(for tunnels: [TunnelConfig]) -> PreloadedPasswords? {
        let credentialKeys = Set(tunnels.compactMap(TunnelCredentialKey.init))
        guard !credentialKeys.isEmpty else {
            return nil
        }

        do {
            return try passwordStore.preloadPasswords(for: credentialKeys)
        } catch {
            globalMessage = "Credential preload failed: \(error.localizedDescription)"
            return nil
        }
    }

    private func prepareTunnelLaunch(
        named name: String,
        tunnel: TunnelConfig,
        allowPasswordPrompt: Bool,
        preloadedPasswords: PreloadedPasswords?
    ) -> PreparedTunnelLaunch? {
        let launchTunnel: TunnelConfig
        let directTunnel: TunnelConfig
        do {
            directTunnel = try preparedTunnelForLaunch(tunnel)
            launchTunnel = GatewayLinker.applyingGatewayProxy(
                to: directTunnel,
                gateways: gateways.map(\.config)
            )
        } catch {
            updateState(for: name, isRunning: false, state: .failed, message: "SSH option setup failed: \(error.localizedDescription)")
            globalMessage = "Failed to prepare SSH options for \(name)."
            return nil
        }

        let preparation: ConnectionPreparation
        do {
            preparation = try connectionPreparation(
                for: launchTunnel,
                allowPasswordPrompt: allowPasswordPrompt,
                preloadedPasswords: preloadedPasswords
            )
        } catch {
            updateState(for: name, isRunning: false, state: .failed, message: "Password setup failed: \(error.localizedDescription)")
            globalMessage = "Failed to prepare credentials for \(name)."
            return nil
        }

        return PreparedTunnelLaunch(name: name, tunnel: launchTunnel, directTunnel: directTunnel, preparation: preparation)
    }

    private func launchPreparedTunnel(_ preparedLaunch: PreparedTunnelLaunch) {
        let name = preparedLaunch.name
        let preparation = preparedLaunch.preparation

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
                tunnel: preparedLaunch.tunnel,
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
        // Manual stop is intentional — don't let its teardown raise a problem.
        notifier.forget(name: name)
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
        clearRetryIndicator(for: name, resetAttempt: true)
        updateState(for: name, isRunning: false, state: .disconnected, message: "Stopping")
        globalMessage = "Stopped \(name)."
    }

    func openSSHTerminal(for name: String) {
        guard let tunnel = tunnels.first(where: { $0.id == name })?.tunnel else {
            globalMessage = "Tunnel '\(name)' not found."
            return
        }
        if let account = linkedTwoFactorAccount(for: tunnel) {
            globalMessage = "Preparing \(account.name) 2FA for \(tunnel.host)."
            Task { @MainActor [weak self] in
                guard let self else { return }
                do {
                    NSApp.activate(ignoringOtherApps: true)
                    let codes = try await self.twoFactorStore.currentAndNextCodes(
                        for: account,
                        reason: "Use the \(account.name) verification code for SSH",
                        at: Date(),
                        unlockCacheSeconds: self.twoFactorUnlockCacheSeconds
                    )
                    try SSHTerminalLauncher.open(
                        tunnel: tunnel,
                        gateways: self.gateways.map(\.config),
                        terminalApp: self.terminalApp,
                        oneTimeCode: SSHTerminalLauncher.OneTimeCode(
                            accountName: account.name,
                            currentCode: codes.current,
                            nextCode: codes.next,
                            periodEnd: codes.periodEnd
                        )
                    )
                    self.globalMessage = "Opening ssh to \(tunnel.host); \(account.name) 2FA will be sent at the token prompt."
                } catch let error as TwoFactorStoreError {
                    do {
                        try self.openPlainSSHTerminal(for: tunnel)
                        self.globalMessage = "Opening normal ssh; \(account.name) 2FA was not prepared (\(error.localizedDescription))."
                    } catch {
                        self.globalMessage = "Couldn't open ssh terminal: \(error.localizedDescription)"
                    }
                } catch {
                    do {
                        try self.openPlainSSHTerminal(for: tunnel)
                        self.globalMessage = "Opening normal ssh; \(account.name) 2FA was not prepared."
                    } catch {
                        self.globalMessage = "Couldn't open ssh terminal: \(error.localizedDescription)"
                    }
                }
            }
            return
        }
        do {
            try openPlainSSHTerminal(for: tunnel)
            globalMessage = "Opening ssh to \(tunnel.host) in \(terminalAppDisplayName)."
        } catch {
            globalMessage = "Couldn't open ssh terminal: \(error.localizedDescription)"
        }
    }

    private func openPlainSSHTerminal(for tunnel: TunnelConfig) throws {
        try SSHTerminalLauncher.open(tunnel: tunnel, gateways: gateways.map(\.config), terminalApp: terminalApp)
    }

    private func linkedTwoFactorAccount(for tunnel: TunnelConfig) -> TwoFactorAccount? {
        func matches(_ value: String?) -> Bool {
            guard let raw = value?.trimmingCharacters(in: .whitespacesAndNewlines), !raw.isEmpty else {
                return false
            }
            return raw == tunnel.name
                || raw == tunnel.host
                || raw == "\(tunnel.user.map { "\($0)@" } ?? "")\(tunnel.host)"
        }

        return twoFactorAccounts.first { matches($0.sshHost) }
            ?? twoFactorAccounts.first { $0.name == tunnel.name }
    }

    var terminalAppDisplayName: String {
        switch normalizedTerminalApp(terminalApp) {
        case "iterm": return "iTerm2"
        case "terminal": return "Terminal"
        default: return "System Default"
        }
    }

    func setTerminalApp(_ value: String) {
        let selected = normalizedTerminalApp(value)
        do {
            var config = try store.load()
            config.terminalApp = selected
            try store.save(config)
            terminalApp = selected
            globalMessage = "SSH sessions will open in \(terminalAppDisplayName)."
        } catch {
            globalMessage = "Failed to save terminal app: \(error.localizedDescription)"
        }
    }

    var twoFactorUnlockCacheDisplayName: String {
        Self.twoFactorUnlockCacheOptions.first(where: { $0.seconds == twoFactorUnlockCacheSeconds })?.label ?? "Every Time"
    }

    struct TwoFactorUnlockCacheOption: Identifiable, Equatable {
        let label: String
        let seconds: Int
        var id: Int { seconds }
    }

    static let twoFactorUnlockCacheOptions: [TwoFactorUnlockCacheOption] = [
        TwoFactorUnlockCacheOption(label: "Every Time", seconds: 0),
        TwoFactorUnlockCacheOption(label: "5 Minutes", seconds: 5 * 60),
        TwoFactorUnlockCacheOption(label: "1 Hour", seconds: 60 * 60),
        TwoFactorUnlockCacheOption(label: "1 Day", seconds: 24 * 60 * 60),
        TwoFactorUnlockCacheOption(label: "1 Week", seconds: 7 * 24 * 60 * 60),
    ]

    func setTwoFactorUnlockCacheSeconds(_ value: Int) {
        let selected = normalizedTwoFactorUnlockCacheSeconds(value)
        do {
            var config = try store.load()
            config.twoFactorUnlockCacheSeconds = selected
            try store.save(config)
            twoFactorUnlockCacheSeconds = selected
            twoFactorStore.clearCache()
            globalMessage = selected == 0
                ? "2FA unlock will ask every time."
                : "2FA unlock will ask every \(twoFactorUnlockCacheDisplayName.lowercased()) while Burrow stays open."
        } catch {
            globalMessage = "Failed to save 2FA unlock setting: \(error.localizedDescription)"
        }
    }

    private func normalizedTerminalApp(_ value: String) -> String {
        switch value.lowercased() {
        case "iterm", "terminal":
            return value.lowercased()
        default:
            // "auto" = the OS default .command handler. Legacy "default"
            // configs collapse into this (same behavior).
            return "auto"
        }
    }

    private func normalizedTwoFactorUnlockCacheSeconds(_ value: Int) -> Int {
        Self.twoFactorUnlockCacheOptions.map(\.seconds).contains(value) ? value : 0
    }

    /// Copies an interactive ssh command for the host, routed through the
    /// tunnel's VPN gateway when it has one — paste it into a terminal or hand
    /// it to an agent to reach the server the same way the tunnel does.
    func copySSHCommand(for name: String) {
        guard let tunnel = tunnels.first(where: { $0.id == name })?.tunnel else {
            globalMessage = "Tunnel '\(name)' not found."
            return
        }
        let routed = GatewayLinker.applyingGatewayProxy(to: tunnel, gateways: gateways.map(\.config))
        let command = SSHTerminalLauncher.interactiveCommand(for: routed)
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(command, forType: .string)
        globalMessage = tunnel.gateway.map { "Copied ssh command (via \($0))." } ?? "Copied ssh command."
    }

    // MARK: - SSH hosts (~/.ssh/config login targets)

    /// Concrete login hosts from ~/.ssh/config (wildcards already excluded by
    /// the parser), surfaced as quick `ssh` targets when showSSHHosts is on.
    var sshHostEntries: [SSHConfigHost] {
        sshConfigHosts
    }

    /// A minimal tunnel standing in for a config host: name == alias so the
    /// launcher emits `ssh <alias>` and inherits the user's full ssh config.
    private func tunnel(forSSHHostAlias alias: String) -> TunnelConfig? {
        guard let host = sshConfigHosts.first(where: { $0.alias == alias }) else {
            return nil
        }
        return TunnelConfig(
            name: host.alias,
            host: host.effectiveHost,
            user: host.user,
            sshPort: host.port ?? 22,
            forwards: []
        )
    }

    /// Prompts for a new login host and appends it to ~/.ssh/config, then
    /// refreshes the Hosts list and expands the section so it's visible.
    func createSSHHost() {
        guard let entry = SSHHostPrompt.request() else {
            return
        }
        do {
            try SSHConfigWriter.appendHost(entry)
            sshConfigHosts = SSHConfigParser.parse()
            toggledSections.insert("hosts")  // default-collapsed → expand to show it
            globalMessage = "Added SSH host \(entry.alias) to ~/.ssh/config."
        } catch {
            globalMessage = "Couldn't add SSH host: \(error.localizedDescription)"
        }
    }

    func openSSHHost(alias: String) {
        guard let tunnel = tunnel(forSSHHostAlias: alias) else {
            globalMessage = "SSH host '\(alias)' not found in ~/.ssh/config."
            return
        }
        do {
            try SSHTerminalLauncher.open(tunnel: tunnel, gateways: [], terminalApp: terminalApp)
            globalMessage = "Opening ssh \(alias) in \(terminalAppDisplayName)."
        } catch {
            globalMessage = "Couldn't open ssh terminal: \(error.localizedDescription)"
        }
    }

    func copySSHHostCommand(alias: String) {
        guard let tunnel = tunnel(forSSHHostAlias: alias) else {
            globalMessage = "SSH host '\(alias)' not found in ~/.ssh/config."
            return
        }
        let command = SSHTerminalLauncher.interactiveCommand(for: tunnel)
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(command, forType: .string)
        globalMessage = "Copied ssh \(alias) command."
    }

    // MARK: - Two-factor (TOTP) codes

    @Published private(set) var twoFactorAccounts: [TwoFactorAccount] = []
    /// Codes currently revealed in the menu, by account name. Each is valid
    /// only until its TOTP period boundary, after which the row re-locks.
    @Published var revealedCodes: [String: RevealedCode] = [:]

    /// Drives the dedicated Authenticator window (kept out of the main menu
    /// while the feature is being refined).
    @Published var showingAuthenticator = false {
        didSet {
            guard oldValue != showingAuthenticator else { return }
            syncAuthenticatorWindow()
        }
    }
    private var authenticatorWindowController: AuthenticatorWindowController?

    let twoFactorStore = TwoFactorStore()

    struct RevealedCode: Equatable {
        let code: String
        let periodEnd: Date
    }

    func openAuthenticator() {
        guard TwoFactorStore.authenticationAvailable() else {
            globalMessage = "Mac authentication isn't available, so verification codes can't be stored securely."
            return
        }
        showingAuthenticator = true
    }

    func closeAuthenticator() {
        showingAuthenticator = false
    }

    private func syncAuthenticatorWindow() {
        if showingAuthenticator {
            if authenticatorWindowController == nil {
                authenticatorWindowController = AuthenticatorWindowController(viewModel: self)
            }
            authenticatorWindowController?.present()
        } else {
            authenticatorWindowController?.dismiss()
        }
    }

    /// Generates and reveals the current code for an account. Presents the
    /// system authentication sheet (off the main thread), copies the code to the
    /// clipboard, and schedules the row to re-lock at the period boundary.
    func revealTwoFactorCode(named name: String) {
        guard let account = twoFactorAccounts.first(where: { $0.id == name }) else {
            return
        }
        Task { @MainActor [weak self] in
            guard let self else { return }
            let now = Date()
            do {
                let code = try await self.twoFactorStore.currentCode(
                    for: account,
                    reason: "Reveal the \(account.name) verification code",
                    at: now,
                    unlockCacheSeconds: self.twoFactorUnlockCacheSeconds
                )
                let periodEnd = now.addingTimeInterval(Double(account.period) - now.timeIntervalSince1970.truncatingRemainder(dividingBy: Double(account.period)))
                self.revealedCodes[name] = RevealedCode(code: code, periodEnd: periodEnd)
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(code, forType: .string)
                self.globalMessage = "Copied \(account.name) code — valid ~\(Int(periodEnd.timeIntervalSince(now)))s."
                // Auto re-lock when the code expires.
                let delay = max(1, periodEnd.timeIntervalSince(Date()))
                Task { @MainActor [weak self] in
                    try? await Task.sleep(for: .seconds(delay))
                    self?.revealedCodes[name] = nil
                }
            } catch let error as TwoFactorStoreError {
                if case .cancelled = error { return }
                self.globalMessage = error.localizedDescription
            } catch {
                self.globalMessage = "Couldn't read the \(account.name) code: \(error.localizedDescription)"
            }
        }
    }

    func hideTwoFactorCode(named name: String) {
        revealedCodes[name] = nil
    }

    /// Enrolls (or re-enrolls) an account from a pasted otpauth URI / base32
    /// secret, storing the seed behind Mac authentication and the params in the config.
    /// Returns true on success so the caller can dismiss its add form.
    @discardableResult
    func enrollTwoFactor(name: String, secret: String) -> Bool {
        let trimmedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedName.isEmpty else {
            globalMessage = "A name is required for the 2FA account."
            return false
        }
        do {
            let parsed = try twoFactorStore.enroll(secretInput: secret, account: trimmedName)
            let account = TwoFactorAccount(
                name: trimmedName,
                digits: parsed.digits,
                period: parsed.period,
                algorithm: parsed.algorithm.rawValue
            )
            try store.upsertTwoFactorAccount(account)
            loadConfig()
            globalMessage = "Saved code for \(trimmedName)."
            return true
        } catch let error as TwoFactorStoreError {
            globalMessage = error.localizedDescription
            return false
        } catch {
            globalMessage = "Couldn't save code: \(error.localizedDescription)"
            return false
        }
    }

    func deleteTwoFactorAccount(named name: String) {
        twoFactorStore.delete(account: name)
        revealedCodes[name] = nil
        do {
            try store.removeTwoFactorAccount(name: name)
            loadConfig()
            globalMessage = "Removed 2FA account \(name)."
        } catch {
            globalMessage = "Couldn't remove 2FA account: \(error.localizedDescription)"
        }
    }

    // MARK: - Profiles

    @Published private(set) var profilesCache: [Profile] = []

    var profiles: [Profile] {
        profilesCache
    }

    enum ProfileRunState {
        case up
        case partial
        case down
    }

    func profileRunState(_ profile: Profile) -> ProfileRunState {
        let tunnelStates = tunnels.filter { profile.tunnels.contains($0.id) }
        let gatewayStates = gateways.filter { profile.gateways.contains($0.id) }
        let total = tunnelStates.count + gatewayStates.count
        guard total > 0 else {
            return .down
        }
        let upCount = tunnelStates.filter { $0.connectionState == .connected }.count
            + gatewayStates.filter { $0.connectionState == .connected }.count
        if upCount == total {
            return .up
        }
        if upCount > 0 || tunnelStates.contains(where: \.isRunning) || gatewayStates.contains(where: \.isRunning) {
            return .partial
        }
        return .down
    }

    func toggleProfile(named name: String) {
        guard let profile = profilesCache.first(where: { $0.name == name }) else {
            return
        }
        let anyActive = tunnels.contains { profile.tunnels.contains($0.id) && $0.isRunning }
            || gateways.contains { profile.gateways.contains($0.id) && $0.isRunning }
        if anyActive {
            stopProfile(named: name)
        } else {
            startProfile(named: name)
        }
    }

    /// New-tunnel editor prefilled from an existing host's siblings (user,
    /// port, identity, jump host, gateway), so adding another forward to a
    /// known host is mostly just picking ports.
    func createTunnel(forHost host: String) {
        gatewayDraft = nil
        profileDraft = nil
        let siblings = tunnels.map(\.tunnel)
        var draft = TunnelDraft.newTunnel(from: siblings, sshHosts: sshConfigHosts)
        draft.host = host
        if let sibling = siblings.first(where: { $0.host == host }) {
            draft.user = sibling.user ?? draft.user
            draft.sshPort = String(sibling.sshPort)
            draft.identityFile = sibling.identityFile ?? draft.identityFile
            draft.jumpHost = sibling.jumpHost ?? draft.jumpHost
            draft.gateway = sibling.gateway ?? ""
        }
        editorDraft = draft
    }

    func startProfile(named name: String) {
        guard let profile = profiles.first(where: { $0.name == name }) else {
            globalMessage = "Profile '\(name)' not found."
            return
        }
        for gatewayName in profile.gateways {
            startGateway(named: gatewayName)
        }
        let toStart = tunnels.filter { profile.tunnels.contains($0.id) }
        startTunnels(toStart, allowPasswordPrompt: true, preloadCredentials: true)
        globalMessage = "Starting profile \(name)."
    }

    func stopProfile(named name: String) {
        guard let profile = profiles.first(where: { $0.name == name }) else {
            return
        }
        for tunnelName in profile.tunnels {
            stopTunnel(named: tunnelName)
        }
        for gatewayName in profile.gateways {
            stopGateway(named: gatewayName)
        }
        globalMessage = "Stopped profile \(name)."
    }

    func createProfile() {
        editorDraft = nil
        gatewayDraft = nil
        profileDraft = ProfileDraft.newProfile(existing: profiles)
    }

    func openProfileEditor(for name: String) {
        guard let profile = profiles.first(where: { $0.name == name }) else {
            globalMessage = "Profile '\(name)' not found."
            return
        }
        editorDraft = nil
        gatewayDraft = nil
        profileDraft = ProfileDraft(profile: profile, originalName: profile.name)
    }

    func closeProfileEditor() {
        profileDraft = nil
    }

    func saveProfileEditor() {
        guard let draft = profileDraft else {
            return
        }
        do {
            let profile = try draft.toProfile()
            try store.upsertProfile(profile, replacing: draft.originalName)
            loadConfig()
            globalMessage = "Saved profile \(profile.name)."
            profileDraft = nil
        } catch {
            globalMessage = "Save failed: \(error.localizedDescription)"
        }
    }

    func deleteProfile(named name: String) {
        do {
            try store.removeProfile(name: name)
            loadConfig()
            globalMessage = "Deleted profile \(name)."
        } catch {
            globalMessage = "Delete failed: \(error.localizedDescription)"
        }
    }

    func deleteProfileEditorTarget() {
        guard let draft = profileDraft, let originalName = draft.originalName else {
            profileDraft = nil
            return
        }
        do {
            try store.removeProfile(name: originalName)
            loadConfig()
            globalMessage = "Deleted profile \(originalName)."
        } catch {
            globalMessage = "Delete failed: \(error.localizedDescription)"
        }
        profileDraft = nil
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
        gatewayDraft = nil
        profileDraft = nil
        editorDraft = TunnelDraft(tunnel: tunnel, originalName: tunnel.name)
    }

    func duplicateTunnel(named name: String) {
        guard let tunnel = tunnels.first(where: { $0.id == name })?.tunnel else {
            globalMessage = "Tunnel '\(name)' not found."
            return
        }

        var draft = TunnelDraft(tunnel: tunnel, originalName: nil)
        draft.name = uniqueDuplicateName(for: tunnel.name)
        gatewayDraft = nil
        profileDraft = nil
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
        gatewayDraft = nil
        profileDraft = nil
        editorDraft = TunnelDraft.newTunnel(from: tunnels.map(\.tunnel), sshHosts: sshConfigHosts)
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
        // Teardown happens in the willTerminate handler (gated by the
        // keep-running setting), which also covers ⌘Q and logout.
        NSApp.terminate(nil)
    }

    private func syncEditorWindow() {
        let title: String?
        if let draft = profileDraft {
            title = draft.originalName.map { "Edit Profile \($0)" } ?? "New Profile"
        } else if let draft = gatewayDraft {
            title = draft.originalName.map { "Edit Gateway \($0)" } ?? "New VPN Gateway"
        } else if let draft = editorDraft {
            title = draft.originalName.map { "Edit \($0)" } ?? "New Tunnel"
        } else {
            title = nil
        }

        if let title {
            if editorWindowController == nil {
                editorWindowController = EditorWindowController(viewModel: self)
            }
            editorWindowController?.present(title: title)
        } else {
            editorWindowController?.dismiss()
        }
    }

    func createGateway() {
        editorDraft = nil
        profileDraft = nil
        gatewayDraft = GatewayDraft.newGateway(from: gateways.map(\.config))
    }

    func openGatewayEditor(for name: String) {
        guard let gateway = gateways.first(where: { $0.id == name })?.config else {
            globalMessage = "Gateway '\(name)' not found."
            return
        }
        editorDraft = nil
        profileDraft = nil
        gatewayDraft = GatewayDraft(gateway: gateway, originalName: gateway.name)
    }

    func closeGatewayEditor() {
        gatewayDraft = nil
    }

    func saveGatewayEditor() {
        guard let draft = gatewayDraft else {
            return
        }

        do {
            let gateway = try draft.toGatewayConfig()
            if let originalName = draft.originalName, originalName != gateway.name, gatewayTasks[originalName] != nil {
                stopGateway(named: originalName)
            } else if gatewayTasks[gateway.name] != nil {
                stopGateway(named: gateway.name)
            }
            try store.upsertGateway(gateway, replacing: draft.originalName)
            loadConfig()
            globalMessage = "Saved gateway \(gateway.name)."
            gatewayDraft = nil
        } catch {
            globalMessage = "Save failed: \(error.localizedDescription)"
        }
    }

    func deleteGatewayEditorTarget() {
        guard let draft = gatewayDraft, let originalName = draft.originalName else {
            return
        }
        deleteGateway(named: originalName)
        gatewayDraft = nil
    }

    func deleteGateway(named name: String) {
        do {
            if gatewayTasks[name] != nil || activeSAMLAuthenticators[name] != nil {
                stopGateway(named: name)
            }
            try store.removeGateway(name: name)
            loadConfig()
            let dependents = tunnels.filter { $0.tunnel.gateway == name }.map(\.id)
            globalMessage = dependents.isEmpty
                ? "Deleted gateway \(name)."
                : "Deleted gateway \(name). Tunnels still referencing it: \(dependents.joined(separator: ", "))."
        } catch {
            globalMessage = "Delete failed: \(error.localizedDescription)"
        }
    }

    private var isBundledApp: Bool {
        Bundle.main.bundlePath.hasSuffix(".app")
    }

    func refreshLaunchAtLoginState() {
        launchAtLoginEnabled = isBundledApp && SMAppService.mainApp.status == .enabled
    }

    func setLaunchAtLogin(_ enabled: Bool) {
        guard isBundledApp else {
            globalMessage = "Start at Login needs the installed app bundle (run scripts/install-app.sh)."
            return
        }

        do {
            if enabled {
                try SMAppService.mainApp.register()
            } else {
                try SMAppService.mainApp.unregister()
            }
            refreshLaunchAtLoginState()
            globalMessage = enabled ? "Burrow will start at login." : "Burrow will no longer start at login."
        } catch {
            refreshLaunchAtLoginState()
            globalMessage = "Start at Login change failed: \(error.localizedDescription)"
        }
    }

    func beginSSHConfigImport() {
        let hosts = SSHConfigParser.parse()
        sshConfigHosts = hosts
        let forwardHosts = hosts.filter { !$0.forwards.isEmpty }

        guard !forwardHosts.isEmpty else {
            globalMessage = hosts.isEmpty
                ? "No usable Host entries found in ~/.ssh/config."
                : "No hosts with forwards in ~/.ssh/config; \(hosts.count) host(s) now feed editor autofill."
            return
        }

        var takenNames = Set(tunnels.map(\.id))
        importCandidates = forwardHosts.map { host in
            let name = Self.uniqueName(base: host.alias, existing: takenNames)
            takenNames.insert(name)
            return SSHConfigImportCandidate(
                host: host,
                include: !tunnels.contains { $0.id == host.alias },
                tunnelName: name
            )
        }
    }

    func cancelSSHConfigImport() {
        importCandidates = nil
    }

    func confirmSSHConfigImport() {
        guard let candidates = importCandidates else {
            return
        }

        var imported = 0
        do {
            for candidate in candidates where candidate.include {
                try store.upsert(candidate.toTunnelConfig())
                imported += 1
            }
            loadConfig()
            globalMessage = "Imported \(imported) tunnel(s) from SSH config."
        } catch {
            loadConfig()
            globalMessage = "Import failed: \(error.localizedDescription)"
        }
        importCandidates = nil
    }

    private static func uniqueName(base: String, existing: Set<String>) -> String {
        guard existing.contains(base) else {
            return base
        }
        var suffix = 2
        while existing.contains("\(base)-\(suffix)") {
            suffix += 1
        }
        return "\(base)-\(suffix)"
    }

    fileprivate func scheduleRetryIndicator(for name: String) {
        guard let index = tunnels.firstIndex(where: { $0.id == name }) else {
            return
        }
        tunnels[index].retryAttempt += 1
        let delay = max(tunnels[index].tunnel.reconnectDelaySeconds, 0)
        tunnels[index].nextRetryAt = Date().addingTimeInterval(TimeInterval(delay))
    }

    fileprivate func clearRetryIndicator(for name: String, resetAttempt: Bool) {
        guard let index = tunnels.firstIndex(where: { $0.id == name }) else {
            return
        }
        tunnels[index].nextRetryAt = nil
        if resetAttempt {
            tunnels[index].retryAttempt = 0
        }
    }

    // MARK: - VPN gateways

    var sshIncludePath: String {
        store.configURL.deletingLastPathComponent().appendingPathComponent("ssh_include").path
    }

    var hasSSHInclude: Bool {
        gateways.contains { !$0.config.sshHostPatterns.isEmpty }
    }

    private func writeSSHInclude(for gateways: [GatewayConfig]) {
        let url = store.configURL.deletingLastPathComponent().appendingPathComponent("ssh_include")
        if let text = GatewayLinker.sshIncludeText(for: gateways) {
            try? text.write(to: url, atomically: true, encoding: .utf8)
        } else {
            try? FileManager.default.removeItem(at: url)
        }
    }

    @discardableResult
    func startGateway(named name: String, allowPasswordPrompt: Bool = true) -> Bool {
        guard gatewayTasks[name] == nil, !adoptedGateways.contains(name) else {
            return true
        }
        guard let gateway = gateways.first(where: { $0.id == name })?.config else {
            globalMessage = "Gateway '\(name)' not found."
            return false
        }

        let missingTools = GatewayToolsInstaller.missingTools
        if !missingTools.isEmpty {
            let missingList = missingTools.joined(separator: ", ")
            guard allowPasswordPrompt else {
                updateGatewayState(for: name, isRunning: false, state: .failed, message: "\(missingList) not installed — click Connect")
                return false
            }
            updateGatewayState(for: name, isRunning: false, state: .failed, message: "\(missingList) not installed")
            if GatewayToolsInstaller.promptAndInstall(missing: missingTools) {
                watchForToolInstall(thenStart: name)
            }
            return false
        }

        if gateway.usesSAML {
            if gateway.vpnProtocol.lowercased() == "gp" {
                guard activeSAMLAuthenticators[name] == nil else {
                    return true
                }
                // A user-initiated connect (or auto-reconnect after a drop) opens
                // the SAML sign-in window for the user to complete. A headless
                // launch auto-start does not pop a window — it reports that a
                // sign-in is needed so the gateway shows "click Connect".
                updateGatewayState(for: name, isRunning: false, state: .connecting, message: "Signing in (SAML)")
                let authenticator = GPSAMLAuthenticator(gateway: gateway)
                activeSAMLAuthenticators[name] = authenticator
                authenticator.begin(interactive: allowPasswordPrompt) { [weak self] result in
                    guard let self else {
                        return
                    }
                    self.activeSAMLAuthenticators[name] = nil
                    switch result {
                    case .success(let saml):
                        self.spawnGatewaySupervisor(
                            gateway,
                            credential: .samlCookie(username: saml.username, cookie: saml.cookie, usergroup: saml.usergroup)
                        )
                    case .failure(let error):
                        self.updateGatewayState(for: name, isRunning: false, state: .failed, message: error.localizedDescription)
                    }
                }
                return true
            }

            if gateway.vpnProtocol.lowercased() == "anyconnect" {
                guard activeSAMLAuthenticators[name] == nil else {
                    return true
                }
                // Modern ASAs won't start SAML inside openconnect's handshake,
                // so sign in via the clientless web logon in an embedded window
                // and hand openconnect the captured webvpn session cookie.
                updateGatewayState(for: name, isRunning: false, state: .connecting, message: "Signing in (SAML)")
                let authenticator = AnyConnectSAMLAuthenticator(gateway: gateway)
                activeSAMLAuthenticators[name] = authenticator
                authenticator.begin(interactive: allowPasswordPrompt) { [weak self] result in
                    guard let self else {
                        return
                    }
                    self.activeSAMLAuthenticators[name] = nil
                    switch result {
                    case .success(let cookie):
                        self.spawnGatewaySupervisor(gateway, credential: .sessionCookie(cookie))
                    case .failure(let error):
                        self.updateGatewayState(for: name, isRunning: false, state: .failed, message: error.localizedDescription)
                    }
                }
                return true
            }

            // Other protocols' SAML opens the system browser, which can't be
            // done silently — only on an explicit Connect.
            guard allowPasswordPrompt else {
                updateGatewayState(for: name, isRunning: false, state: .failed, message: "SAML sign-in needed — click Connect")
                return false
            }
            spawnGatewaySupervisor(gateway, credential: .samlExternalBrowser)
            globalMessage = "Gateway \(name): complete the sign-in in your browser."
            return true
        }

        var credential: GatewayCredential = .none
        var pendingSave: PendingCredentialSave?
        if let credentialKey = TunnelCredentialKey(gateway: gateway) {
            let isRetry = invalidGatewayCredentialKeys.contains(credentialKey)
            let savedPassword = isRetry ? nil : ((try? passwordStore.password(for: credentialKey)) ?? nil)
            if let savedPassword, !savedPassword.isEmpty {
                credential = .password(savedPassword)
            } else if allowPasswordPrompt {
                guard let entered = PasswordPrompt.requestVPNPassword(
                    gatewayName: gateway.name,
                    server: gateway.server,
                    user: credentialKey.user,
                    retry: isRetry
                ) else {
                    updateGatewayState(for: name, isRunning: false, state: .disconnected, message: "Password entry cancelled")
                    return false
                }
                credential = .password(entered)
                pendingSave = PendingCredentialSave(key: credentialKey, password: entered)
            } else {
                updateGatewayState(for: name, isRunning: false, state: .failed, message: "No saved VPN password — connect manually once")
                return false
            }
        }

        spawnGatewaySupervisor(gateway, credential: credential, pendingSave: pendingSave)
        return true
    }

    /// Polls until the Homebrew install finishes, then connects the gateway.
    private func watchForToolInstall(thenStart name: String) {
        toolInstallWatchTask?.cancel()
        updateGatewayState(for: name, isRunning: false, state: .connecting, message: "Waiting for Homebrew install to finish")
        globalMessage = "Installing VPN tools in Terminal; \(name) connects when done."
        toolInstallWatchTask = Task { @MainActor [weak self] in
            let deadline = Date().addingTimeInterval(900)
            while Date() < deadline, !Task.isCancelled {
                if GatewayToolsInstaller.missingTools.isEmpty {
                    self?.globalMessage = "VPN tools installed — connecting \(name)."
                    self?.startGateway(named: name)
                    return
                }
                try? await Task.sleep(for: .seconds(2))
            }
            guard !Task.isCancelled else {
                return
            }
            self?.updateGatewayState(for: name, isRunning: false, state: .failed, message: "Install didn't finish — connect again once brew completes")
        }
    }

    private func spawnGatewaySupervisor(_ gateway: GatewayConfig, credential: GatewayCredential, pendingSave: PendingCredentialSave? = nil) {
        let name = gateway.name
        guard gatewayTasks[name] == nil else {
            return
        }

        pendingGatewayCredentialSaves[name] = pendingSave
        updateGatewayState(for: name, isRunning: true, state: .connecting, message: "Connecting VPN")
        let bridge = GatewayEventBridge(owner: self, gatewayName: name)
        let task = Task.detached(priority: .userInitiated) {
            let supervisor = GatewaySupervisor(
                gateway: gateway,
                credential: credential,
                logger: { message in
                    bridge.log(message)
                },
                eventHandler: { event in
                    bridge.handle(event)
                }
            )
            await supervisor.run()
            bridge.finish()
        }
        gatewayTasks[name] = task
        globalMessage = "Starting gateway \(name)."
    }

    func stopGateway(named name: String) {
        if let authenticator = activeSAMLAuthenticators[name] {
            activeSAMLAuthenticators[name] = nil
            authenticator.cancel()
        }
        // A deliberate stop must not trigger automatic SAML re-sign-in.
        samlSessionConnectedAt[name] = nil
        samlReauthAttempts[name] = 0

        guard let task = gatewayTasks[name] else {
            if adoptedGateways.remove(name) != nil,
               let config = gateways.first(where: { $0.id == name })?.config {
                // Adopted sessions have no supervisor task; tear down their
                // processes directly.
                GatewayPortReclaimer.killGatewayProcesses(socksPort: config.socksPort, server: config.server)
                updateGatewayState(for: name, isRunning: false, state: .disconnected, message: "Stopped")
                globalMessage = "Stopped gateway \(name)."
            } else {
                updateGatewayState(for: name, isRunning: false, state: .disconnected, message: "Not running")
            }
            return
        }
        task.cancel()
        gatewayTasks[name] = nil
        pendingGatewayCredentialSaves[name] = nil
        updateGatewayState(for: name, isRunning: false, state: .disconnected, message: "Stopped")

        let dependents = tunnels.filter { $0.tunnel.gateway == name && $0.isRunning }.map(\.id)
        globalMessage = dependents.isEmpty
            ? "Stopped gateway \(name)."
            : "Stopped gateway \(name); dependent tunnels will keep retrying: \(dependents.joined(separator: ", "))."
    }

    func stopAllGateways() {
        for name in Array(gatewayTasks.keys) {
            stopGateway(named: name)
        }
    }

    private func stopMissingGateways() {
        let configuredNames = Set((try? store.load().gateways.map(\.name)) ?? [])
        for name in gatewayTasks.keys where !configuredNames.contains(name) {
            stopGateway(named: name)
        }
        for name in adoptedGateways where !configuredNames.contains(name) {
            stopGateway(named: name)
        }
    }

    /// Starts the tunnel once its gateway's SOCKS port answers, starting the
    /// gateway first when needed.
    private func launchWhenGatewayReady(_ prepared: PreparedTunnelLaunch, allowGatewayPrompt: Bool) {
        guard let gatewayName = prepared.tunnel.gateway else {
            launchPreparedTunnel(prepared)
            return
        }
        guard let gatewayConfig = gateways.first(where: { $0.id == gatewayName })?.config else {
            updateState(for: prepared.name, isRunning: false, state: .failed, message: "Gateway '\(gatewayName)' is not defined in the config")
            return
        }

        let socksPort = gatewayConfig.socksPort
        let targetHost = prepared.tunnel.host
        let targetPort = prepared.tunnel.sshPort

        updateState(for: prepared.name, isRunning: false, state: .connecting, message: "Waiting for gateway \(gatewayName)")
        Task { @MainActor [weak self] in
            guard let self else { return }
            // Adopt a working proxy if one is already there — e.g. a VPN left
            // running by a previous Burrow session. If it can reach the target,
            // use it directly instead of forcing a fresh (SAML) reconnect.
            let alreadyReachable = await Task.detached {
                SOCKSProbe.canReach(proxyPort: socksPort, targetHost: targetHost, targetPort: targetPort)
            }.value
            if alreadyReachable {
                self.adoptExternalGatewayIfNeeded(gatewayName)
                self.launchPreparedTunnel(prepared)
                return
            }

            // Burrow's own proxy isn't serving this. Before starting one, check
            // whether the system already routes the target directly — i.e. the
            // user's official VPN client (GlobalProtect/AnyConnect) is connected
            // to the same network. If so, ride it and DON'T start a competing
            // openconnect: logging into the same SSO VPN a second time makes the
            // portal drop one session, interrupting the official connection.
            let burrowGatewayRunning = self.gatewayTasks[gatewayName] != nil || self.adoptedGateways.contains(gatewayName)
            if !burrowGatewayRunning {
                let systemRoutesTarget = await Task.detached {
                    PortProbe.canConnect(host: targetHost, port: targetPort, timeout: 3)
                }.value
                if systemRoutesTarget {
                    self.updateGatewayState(for: gatewayName, isRunning: false, state: .disconnected, message: "Reachable via your system VPN — Burrow gateway left off to avoid a conflict")
                    self.launchPreparedTunnel(PreparedTunnelLaunch(
                        name: prepared.name,
                        tunnel: prepared.directTunnel,
                        directTunnel: prepared.directTunnel,
                        preparation: prepared.preparation
                    ))
                    return
                }
            }

            // Otherwise bring the gateway up (no-op if already starting/running).
            guard self.startGateway(named: gatewayName, allowPasswordPrompt: allowGatewayPrompt) else {
                self.updateState(for: prepared.name, isRunning: false, state: .failed, message: "Gateway \(gatewayName) is not running")
                return
            }

            let deadline = Date().addingTimeInterval(180)
            while Date() < deadline {
                if self.tasks[prepared.name] != nil {
                    return
                }
                let owned = self.gatewayTasks[gatewayName] != nil || self.activeSAMLAuthenticators[gatewayName] != nil
                // Readiness = the proxy can resolve and reach the tunnel's host,
                // not merely that ocproxy's listener is open. ocproxy accepts
                // connections seconds before the VPN's DNS is usable; launching
                // ssh in that window fails as "could not resolve hostname."
                let reachable = await Task.detached {
                    SOCKSProbe.canReach(proxyPort: socksPort, targetHost: targetHost, targetPort: targetPort)
                }.value
                if reachable {
                    self.adoptExternalGatewayIfNeeded(gatewayName)
                    self.launchPreparedTunnel(prepared)
                    return
                }
                if !owned {
                    self.updateState(for: prepared.name, isRunning: false, state: .failed, message: "Gateway \(gatewayName) did not connect")
                    return
                }
                try? await Task.sleep(for: .milliseconds(800))
            }
            self.updateState(for: prepared.name, isRunning: false, state: .failed, message: "Timed out waiting for gateway \(gatewayName)")
        }
    }

    /// Reflects an externally-running (adopted) gateway as connected in the UI
    /// when Burrow itself didn't start it this session.
    private func adoptExternalGatewayIfNeeded(_ name: String) {
        guard gatewayTasks[name] == nil,
              let index = gateways.firstIndex(where: { $0.id == name }),
              gateways[index].connectionState != .connected else {
            return
        }
        gateways[index].isRunning = true
        gateways[index].connectionState = .connected
        gateways[index].lastMessage = "Connected (existing session)"
    }

    fileprivate func updateGatewayState(for name: String, isRunning: Bool, state: ConnectionState? = nil, message: String) {
        guard let index = gateways.firstIndex(where: { $0.id == name }) else {
            return
        }
        gateways[index].isRunning = isRunning
        if let state {
            gateways[index].connectionState = state
        }
        gateways[index].lastMessage = message
    }

    fileprivate func appendGatewayLog(for name: String, message: String) {
        guard let index = gateways.firstIndex(where: { $0.id == name }) else {
            return
        }
        let trimmed = message.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return
        }
        gateways[index].recentLogs.append(trimmed)
        if gateways[index].recentLogs.count > 20 {
            gateways[index].recentLogs.removeFirst(gateways[index].recentLogs.count - 20)
        }
    }

    fileprivate func markGatewayConnected(named name: String) {
        samlSessionConnectedAt[name] = Date()
        samlReauthAttempts[name] = 0

        // The gateway may have come up after a tunnel's wait-for-gateway window
        // expired (slow SAML / manual connect). Re-launch its dependent tunnels
        // that are still trying — enabled, not running, and not cleanly stopped
        // by the user (which leaves them .disconnected).
        let dependents = tunnels.filter {
            $0.tunnel.gateway == name
                && $0.isConfiguredEnabled
                && !$0.isRunning
                && $0.connectionState != .disconnected
        }
        for dependent in dependents {
            startTunnel(named: dependent.id, allowPasswordPrompt: false)
        }
    }

    fileprivate func finishGateway(named name: String) {
        gatewayTasks[name] = nil
        pendingGatewayCredentialSaves[name] = nil
        let connectedAt = samlSessionConnectedAt.removeValue(forKey: name)
        let state: ConnectionState = gateways.first(where: { $0.id == name })?.connectionState == .failed ? .failed : .disconnected
        updateGatewayState(for: name, isRunning: false, state: state, message: state == .failed ? "VPN connection failed" : "Stopped")

        // SAML cookies are single-use, so a dropped session can't simply
        // retry — but the IdP session usually allows a silent re-sign-in.
        // Guarded so a flapping gateway can't loop: the session must have
        // genuinely connected and lived a while, with few recent attempts.
        guard let gateway = gateways.first(where: { $0.id == name })?.config,
              gateway.usesSAML,
              ["gp", "anyconnect"].contains(gateway.vpnProtocol.lowercased()),
              let connectedAt,
              Date().timeIntervalSince(connectedAt) > 30,
              samlReauthAttempts[name, default: 0] < 3 else {
            return
        }

        let attempt = samlReauthAttempts[name, default: 0] + 1
        samlReauthAttempts[name] = attempt
        globalMessage = "Gateway \(name) dropped — signing in again."
        // Progressive backoff so a flapping network doesn't hammer the IdP.
        let backoff = min(2 * attempt, 15)
        Task { @MainActor [weak self] in
            try? await Task.sleep(for: .seconds(backoff))
            guard let self, self.gatewayTasks[name] == nil, self.activeSAMLAuthenticators[name] == nil else {
                return
            }
            // allowPasswordPrompt: true uses the interactive policy, so a stale
            // IdP session reveals the sign-in window instead of silently failing.
            self.startGateway(named: name, allowPasswordPrompt: true)
        }
    }

    fileprivate func persistGatewayPasswordIfNeeded(for name: String) {
        guard let pendingSave = pendingGatewayCredentialSaves[name] else {
            return
        }
        do {
            try passwordStore.save(password: pendingSave.password, for: pendingSave.key)
            pendingGatewayCredentialSaves[name] = nil
            invalidGatewayCredentialKeys.remove(pendingSave.key)
            globalMessage = "Saved VPN password for \(pendingSave.key.account) in Keychain."
        } catch {
            globalMessage = "VPN connected, but failed to save password: \(error.localizedDescription)"
        }
    }

    /// Opens a proxied browser instance through the gateway, starting the
    /// gateway first when needed.
    func openBrowser(_ browser: ChromiumBrowser, viaGateway name: String) {
        guard let gateway = gateways.first(where: { $0.id == name })?.config else {
            globalMessage = "Gateway '\(name)' not found."
            return
        }

        if gatewayTasks[name] != nil && PortProbe.canConnect(host: "127.0.0.1", port: gateway.socksPort) {
            launchBrowser(browser, through: gateway)
            return
        }

        guard startGateway(named: name) else {
            return
        }
        globalMessage = "Starting \(name); \(browser.displayName) opens when the VPN is up."
        Task { @MainActor [weak self] in
            let deadline = Date().addingTimeInterval(150)
            while Date() < deadline {
                guard let self else {
                    return
                }
                if self.gatewayTasks[name] == nil && self.activeSAMLAuthenticators[name] == nil {
                    self.globalMessage = "Gateway \(name) did not connect; browser not opened."
                    return
                }
                if PortProbe.canConnect(host: "127.0.0.1", port: gateway.socksPort) {
                    self.launchBrowser(browser, through: gateway)
                    return
                }
                try? await Task.sleep(for: .milliseconds(500))
            }
            self?.globalMessage = "Timed out waiting for gateway \(name); browser not opened."
        }
    }

    private func launchBrowser(_ browser: ChromiumBrowser, through gateway: GatewayConfig) {
        do {
            try ChromiumBrowserLauncher.launch(browser, through: gateway)
            globalMessage = "Opened \(browser.displayName) via \(gateway.name) (socks :\(gateway.socksPort))."
        } catch {
            globalMessage = "Failed to open \(browser.displayName): \(error.localizedDescription)"
        }
    }

    /// Assigns (or clears) the gateway for a set of tunnels and restarts the
    /// running ones so the new route applies immediately.
    func setGateway(_ gatewayName: String?, forTunnels names: [String]) {
        do {
            var config = try store.load()
            var changed: [String] = []
            for index in config.tunnels.indices where names.contains(config.tunnels[index].name) {
                if config.tunnels[index].gateway != gatewayName {
                    config.tunnels[index].gateway = gatewayName
                    changed.append(config.tunnels[index].name)
                }
            }
            guard !changed.isEmpty else {
                return
            }
            try store.save(config)
            loadConfig()

            let routeLabel = gatewayName.map { "via \($0)" } ?? "directly"
            let subject = changed.count == 1 ? changed[0] : "\(changed.count) tunnels"
            globalMessage = "Routing \(subject) \(routeLabel)."

            for name in changed where tasks[name] != nil {
                restartTunnel(named: name)
            }
        } catch {
            globalMessage = "Failed to change gateway: \(error.localizedDescription)"
        }
    }

    fileprivate func handleGatewayCertificateUntrusted(for name: String, suggestedPin: String) {
        guard let gateway = gateways.first(where: { $0.id == name })?.config else {
            return
        }
        updateGatewayState(for: name, isRunning: false, state: .failed, message: "Server certificate not trusted")

        let alert = NSAlert()
        alert.messageText = "Trust the VPN server certificate for \(gateway.server)?"
        alert.informativeText = "openconnect could not verify this server's certificate — it uses its own CA bundle, not the macOS Keychain, so this is common even when the official client connects fine.\n\nCertificate fingerprint:\n\(suggestedPin)\n\nTrusting pins exactly this certificate for this gateway (saved in its extra arguments)."
        alert.alertStyle = .warning
        alert.addButton(withTitle: "Trust and Reconnect")
        alert.addButton(withTitle: "Cancel")

        guard alert.runModal() == .alertFirstButtonReturn else {
            globalMessage = "Gateway \(name): server certificate was not trusted."
            return
        }

        do {
            var updated = gateway
            updated.extraArgs.removeAll {
                $0 == "--servercert" || $0.hasPrefix("--servercert=") || $0.hasPrefix("pin-sha256:")
            }
            updated.extraArgs.append("--servercert=\(suggestedPin)")
            try store.upsertGateway(updated, replacing: name)
            loadConfig()
            globalMessage = "Pinned certificate for \(name); reconnecting."
            // Let the failed supervisor finish tearing down before relaunching.
            Task { @MainActor [weak self] in
                try? await Task.sleep(for: .milliseconds(400))
                self?.startGateway(named: name)
            }
        } catch {
            globalMessage = "Failed to save certificate pin: \(error.localizedDescription)"
        }
    }

    fileprivate func handleGatewayAuthenticationFailure(for name: String) {
        guard let gateway = gateways.first(where: { $0.id == name })?.config,
              let credentialKey = TunnelCredentialKey(gateway: gateway) else {
            return
        }
        invalidGatewayCredentialKeys.insert(credentialKey)
        pendingGatewayCredentialSaves[name] = nil
        try? passwordStore.deletePassword(for: credentialKey)
        globalMessage = "VPN password for \(credentialKey.account) was rejected. Connect again to re-enter it."
    }

    private func connectionPreparation(
        for tunnel: TunnelConfig,
        allowPasswordPrompt: Bool,
        preloadedPasswords: PreloadedPasswords? = nil
    ) throws -> ConnectionPreparation {
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

            let savedPassword: String?
            if let preloadedPasswords {
                savedPassword = preloadedPasswords.password(for: credentialKey)
            } else {
                savedPassword = try passwordStore.password(for: credentialKey)
            }

            if let password = savedPassword, !password.isEmpty {
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

        // No stored password. Don't prompt up front — launch without an askpass
        // helper so ssh tries publickey/agent first. Key-authenticated tunnels
        // (very common) then never see a password dialog. If ssh actually
        // rejects auth, finishTunnel prompts lazily and retries.
        return ConnectionPreparation(environment: [:], pendingSave: nil, credentialSource: .none)
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
        let oldState = tunnels[index].connectionState
        let tunnel = tunnels[index].tunnel
        tunnels[index].isRunning = isRunning
        if let state {
            tunnels[index].connectionState = state
            if state == .failed {
                if !isRunning, tunnels[index].failedAt == nil {
                    tunnels[index].failedAt = Date()
                }
            } else {
                tunnels[index].failedAt = nil
            }
        }
        tunnels[index].lastMessage = message

        if let state, state != oldState {
            handleStateTransition(tunnel: tunnel, from: oldState, to: state, message: message)
        }
    }

    /// Fires lifecycle hooks and coalesced notifications on real state edges.
    private func handleStateTransition(tunnel: TunnelConfig, from old: ConnectionState, to new: ConnectionState, message: String) {
        let name = tunnel.name
        switch new {
        case .connected where old != .connected:
            HookRunner.run(tunnel.onConnect, event: .connected, tunnel: tunnel)
            notifier.reportRecovery(name: name)
        case .failed:
            if old == .connected {
                HookRunner.run(tunnel.onDisconnect, event: .disconnected, tunnel: tunnel)
                notifier.reportProblem(name: name, reason: message)
            } else if message.localizedCaseInsensitiveContains("authentication failed")
                || message.localizedCaseInsensitiveContains("permission denied") {
                notifier.reportProblem(name: name, reason: message)
            }
        case .disconnected where old == .connected:
            HookRunner.run(tunnel.onDisconnect, event: .disconnected, tunnel: tunnel)
            notifier.forget(name: name)
        default:
            break
        }
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

        let authFailed = sawAuthenticationFailure.contains(name)
        let priorSource = activeCredentialSources[name]
        if authFailed {
            handleAuthenticationFailure(for: name)
        }
        activeCredentialSources[name] = nil
        sawAuthenticationFailure.remove(name)
        clearRetryIndicator(for: name, resetAttempt: true)
        let state: ConnectionState = tunnels.first(where: { $0.id == name })?.connectionState == .failed ? .failed : .disconnected
        updateState(for: name, isRunning: false, state: state, message: state == .failed ? "Connect failed" : "Stopped")

        guard authFailed else {
            return
        }

        // ssh rejected authentication. Now — and only now — prompt for a
        // password and retry, so key-authenticated tunnels never see a dialog.
        // A "retry" prompt means a password we supplied was the one rejected.
        let passwordWasTried: Bool
        switch priorSource {
        case .keychain, .prompted:
            passwordWasTried = true
        default:
            passwordWasTried = false
        }

        guard tunnelPromptAllowed[name] == true,
              shouldAutoPromptAgain(for: name),
              let tunnel = tunnels.first(where: { $0.id == name })?.tunnel,
              let credentialKey = TunnelCredentialKey(tunnel: tunnel) else {
            return
        }

        guard let password = PasswordPrompt.requestPassword(for: credentialKey, tunnelName: name, retry: passwordWasTried),
              !password.isEmpty else {
            return
        }

        sessionPasswords[credentialKey] = password
        sessionPasswordsByHostUser[credentialKey.hostUserKey] = password
        invalidCredentialKeys.remove(credentialKey)
        authRePromptCounts[name, default: 0] += 1
        globalMessage = "Reconnecting \(name) with the password you entered."
        Task { @MainActor [weak self] in
            self?.startTunnel(named: name)
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
                self.owner?.clearRetryIndicator(for: self.tunnelName, resetAttempt: false)
                self.owner?.updateState(for: self.tunnelName, isRunning: true, state: .connecting, message: "Connecting")
            case .connected:
                self.owner?.persistPasswordIfNeeded(for: self.tunnelName)
                self.owner?.resetAuthRePromptCount(for: self.tunnelName)
                self.owner?.clearRetryIndicator(for: self.tunnelName, resetAttempt: true)
                self.owner?.updateState(for: self.tunnelName, isRunning: true, state: .connected, message: "Connected")
            case .authenticationFailed(let message):
                self.owner?.recordAuthenticationFailure(for: self.tunnelName)
                self.owner?.updateState(for: self.tunnelName, isRunning: false, state: .failed, message: "Authentication failed: \(message)")
                self.owner?.globalMessage = "\(self.tunnelName): authentication failed. \(message)"
            case .exited(let code, let diagnostic):
                let message = diagnostic.map { "ssh exited \(code): \($0); retrying" } ?? "ssh exited \(code); retrying"
                self.owner?.scheduleRetryIndicator(for: self.tunnelName)
                self.owner?.updateState(for: self.tunnelName, isRunning: true, state: .failed, message: message)
                self.owner?.globalMessage = diagnostic.map { "\(self.tunnelName): \($0). Retrying." } ?? "\(self.tunnelName): ssh exited with code \(code). Retrying."
            case .failedToStart(let message):
                self.owner?.scheduleRetryIndicator(for: self.tunnelName)
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

final class GatewayEventBridge: @unchecked Sendable {
    weak var owner: MenuBarViewModel?
    let gatewayName: String

    init(owner: MenuBarViewModel, gatewayName: String) {
        self.owner = owner
        self.gatewayName = gatewayName
    }

    func log(_ message: String) {
        Task { @MainActor in
            self.owner?.appendGatewayLog(for: self.gatewayName, message: message)
        }
    }

    func handle(_ event: GatewayRuntimeEvent) {
        Task { @MainActor in
            switch event {
            case .starting:
                self.owner?.updateGatewayState(for: self.gatewayName, isRunning: true, state: .connecting, message: "Connecting VPN")
            case .connected:
                self.owner?.persistGatewayPasswordIfNeeded(for: self.gatewayName)
                self.owner?.markGatewayConnected(named: self.gatewayName)
                self.owner?.updateGatewayState(for: self.gatewayName, isRunning: true, state: .connected, message: "Connected")
                self.owner?.globalMessage = "Gateway \(self.gatewayName) connected."
            case .certificateUntrusted(let suggestedPin):
                self.owner?.handleGatewayCertificateUntrusted(for: self.gatewayName, suggestedPin: suggestedPin)
            case .authenticationFailed(let message):
                self.owner?.handleGatewayAuthenticationFailure(for: self.gatewayName)
                self.owner?.updateGatewayState(for: self.gatewayName, isRunning: false, state: .failed, message: "Authentication failed: \(message)")
            case .exited(let code, let diagnostic):
                let message = diagnostic.map { "openconnect exited \(code): \($0); retrying" } ?? "openconnect exited \(code); retrying"
                self.owner?.updateGatewayState(for: self.gatewayName, isRunning: true, state: .failed, message: message)
            case .failedToStart(let message):
                self.owner?.updateGatewayState(for: self.gatewayName, isRunning: false, state: .failed, message: message)
                self.owner?.globalMessage = "Gateway \(self.gatewayName): \(message)"
            case .log:
                break
            }
        }
    }

    func finish() {
        Task { @MainActor in
            self.owner?.finishGateway(named: self.gatewayName)
        }
    }
}

struct MenuBarContent: View {
    @ObservedObject var viewModel: MenuBarViewModel
    private let menuWidth: CGFloat = 450
    private let minimumMenuHeight: CGFloat = 400

    struct EndpointGroup: Identifiable {
        let endpoint: String
        let hostForNewTunnel: String
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
            if viewModel.importCandidates != nil {
                SSHConfigImportView(
                    candidates: importCandidatesBinding,
                    onCancel: { viewModel.cancelSSHConfigImport() },
                    onImport: { viewModel.confirmSSHConfigImport() }
                )
                .padding(12)
            } else {
                if viewModel.tunnels.isEmpty {
                    if viewModel.gateways.isEmpty {
                        emptyState
                            .padding(16)
                    } else {
                        ScrollView {
                            VStack(alignment: .leading, spacing: 10) {
                                gatewaysSection
                                emptyState
                                    .padding(.horizontal, 4)
                                    .padding(.vertical, 6)
                            }
                            .padding(.horizontal, 12)
                            .padding(.vertical, 10)
                        }
                        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
                    }
                } else {
                    if !viewModel.profiles.isEmpty {
                        profileChipsRow
                        Divider()
                            .opacity(0.5)
                    }
                    ScrollView {
                        VStack(alignment: .leading, spacing: 10) {
                            if !viewModel.gateways.isEmpty {
                                gatewaysSection
                            }
                            ForEach(endpointGroups) { group in
                                let groupExpanded = viewModel.isSectionExpanded("group:\(group.id)", defaultExpanded: true)
                                VStack(alignment: .leading, spacing: 5) {
                                    EndpointHeader(
                                        group: group,
                                        gatewayNames: viewModel.gateways.map(\.id),
                                        isExpanded: groupExpanded,
                                        onToggleCollapse: { viewModel.toggleSection("group:\(group.id)") },
                                        onSelectGateway: { gatewayName in
                                            viewModel.setGateway(gatewayName, forTunnels: group.tunnels.map(\.id))
                                        },
                                        onAddTunnel: { viewModel.createTunnel(forHost: group.hostForNewTunnel) }
                                    )

                                    if groupExpanded {
                                    VStack(alignment: .leading, spacing: 0) {
                                        ForEach(Array(group.tunnels.enumerated()), id: \.element.id) { index, tunnel in
                                            if index > 0 {
                                                Divider()
                                                    .opacity(0.34)
                                                    .padding(.leading, 42)
                                            }
                                            TunnelRow(
                                                tunnel: tunnel,
                                                gatewayNames: viewModel.gateways.map(\.id),
                                                onStart: { viewModel.startTunnel(named: tunnel.id) },
                                                onStop: { viewModel.stopTunnel(named: tunnel.id) },
                                                onRestart: { viewModel.restartTunnel(named: tunnel.id) },
                                                onEdit: { viewModel.openEditor(for: tunnel.id) },
                                                onDuplicate: { viewModel.duplicateTunnel(named: tunnel.id) },
                                                onDelete: { viewModel.deleteTunnel(named: tunnel.id) },
                                                onToggleAutoConnect: { viewModel.setAutoConnect(named: tunnel.id, enabled: $0) },
                                                onSetGateway: { viewModel.setGateway($0, forTunnels: [tunnel.id]) },
                                                onOpenSSH: { viewModel.openSSHTerminal(for: tunnel.id) },
                                                onCopySSH: { viewModel.copySSHCommand(for: tunnel.id) }
                                            )
                                        }
                                    }
                                    .background(
                                        RoundedRectangle(cornerRadius: 16, style: .continuous)
                                            .fill(Color(nsColor: .controlBackgroundColor).opacity(0.54))
                                    )
                                    .overlay(
                                        RoundedRectangle(cornerRadius: 16, style: .continuous)
                                            .stroke(Color.primary.opacity(0.06), lineWidth: 1)
                                    )
                                    .shadow(color: Color.black.opacity(0.045), radius: 6, x: 0, y: 3)
                                    }
                                }
                            }
                            if !viewModel.sshHostEntries.isEmpty {
                                hostsSection
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
                    .background(Color.primary.opacity(0.035))
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
        if viewModel.importCandidates != nil {
            return 620
        }

        let listHeight = endpointGroups.reduce(CGFloat(0)) { total, group in
            let groupHeaderAndSpacing: CGFloat = 32
            let interGroupSpacing: CGFloat = 10
            guard viewModel.isSectionExpanded("group:\(group.id)", defaultExpanded: true) else {
                return total + groupHeaderAndSpacing + interGroupSpacing
            }
            let tunnelCount = CGFloat(group.tunnels.count)
            let dividerHeight = CGFloat(max(group.tunnels.count - 1, 0))
            let rowHeight: CGFloat = 56
            return total + groupHeaderAndSpacing + (tunnelCount * rowHeight) + dividerHeight + interGroupSpacing
        }

        let gatewaysHeight: CGFloat = viewModel.gateways.isEmpty
            ? 0
            : 32 + CGFloat(viewModel.gateways.count) * 56 + CGFloat(max(viewModel.gateways.count - 1, 0)) + 10

        let profileChipsHeight: CGFloat = viewModel.profiles.isEmpty ? 0 : 40

        let hostsHeight: CGFloat
        if viewModel.sshHostEntries.isEmpty {
            hostsHeight = 0
        } else if viewModel.isSectionExpanded("hosts", defaultExpanded: false) {
            hostsHeight = 32 + CGFloat(viewModel.sshHostEntries.count) * 48 + CGFloat(max(viewModel.sshHostEntries.count - 1, 0)) + 10
        } else {
            hostsHeight = 32 // collapsed: header only
        }

        // Footer is a single row now.
        let headerAndFooterChrome: CGFloat = 134
        let emptyStateHeight: CGFloat = viewModel.tunnels.isEmpty ? 70 : 0
        return headerAndFooterChrome + profileChipsHeight + gatewaysHeight + listHeight + hostsHeight + emptyStateHeight
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 7) {
            HStack {
                Text("Burrow")
                    .font(.system(size: 20, weight: .bold))
                    .tracking(-0.45)
                Spacer()
                if viewModel.importCandidates == nil {
                    HealthSummaryPill(tunnels: viewModel.tunnels)
                } else {
                    HeaderPill(text: "Import")
                }
            }
            Text(viewModel.globalMessage)
                .font(.system(size: 11.2, weight: .semibold))
                .foregroundStyle(.secondary.opacity(0.86))
                .lineLimit(1)
                .truncationMode(.tail)
                .help(viewModel.globalMessage)
        }
    }

    private var emptyState: some View {
        VStack(alignment: .leading, spacing: 7) {
            Text("No tunnels saved.")
                .font(.system(size: 13, weight: .medium))
            Text("Click New Tunnel below to create one, or use Settings → Import from SSH Config to pull in existing forwards.")
                .font(.system(size: 11))
                .foregroundStyle(.secondary)
        }
    }

    private var footer: some View {
        HStack(spacing: 8) {
            Menu {
                // Bulk actions: auto-connect covers daily use, so these live
                // here as plain-named occasional tools.
                Button("Connect All Tunnels", action: viewModel.startAll)
                Button("Stop All Tunnels", action: viewModel.stopAll)

                Divider()

                // Manage (creates live in the footer; chips start/stop profiles)
                let profiles = viewModel.profiles
                if !profiles.isEmpty {
                    Menu("Profiles") {
                        ForEach(profiles) { profile in
                            Button("Edit \(profile.name)…") {
                                viewModel.openProfileEditor(for: profile.name)
                            }
                        }
                    }
                }
                Button("Import Tunnels from SSH Config…", action: viewModel.beginSSHConfigImport)
                Button("Authenticator (2FA Codes)…", action: viewModel.openAuthenticator)

                Divider()

                // Preferences
                Toggle("Start at Login", isOn: Binding(
                    get: { viewModel.launchAtLoginEnabled },
                    set: { viewModel.setLaunchAtLogin($0) }
                ))
                Toggle("Keep Running After Quit", isOn: Binding(
                    get: { viewModel.keepRunningAfterQuit },
                    set: { viewModel.keepRunningAfterQuit = $0 }
                ))
                Menu("Open SSH In: \(viewModel.terminalAppDisplayName)") {
                    Button("System Default") { viewModel.setTerminalApp("auto") }
                    Button("iTerm2") { viewModel.setTerminalApp("iterm") }
                    Button("Terminal") { viewModel.setTerminalApp("terminal") }
                }
                Menu("2FA Unlock: \(viewModel.twoFactorUnlockCacheDisplayName)") {
                    ForEach(MenuBarViewModel.twoFactorUnlockCacheOptions, id: \.seconds) { option in
                        Button(option.label) {
                            viewModel.setTwoFactorUnlockCacheSeconds(option.seconds)
                        }
                    }
                }

                Divider()

                // Config file
                Menu("Config File") {
                    Button("Reload", action: viewModel.reloadConfig)
                    Button("Edit JSON…", action: viewModel.openConfig)
                    Button("Reveal in Finder", action: viewModel.revealConfigFolder)
                    if viewModel.hasSSHInclude {
                        Divider()
                        Button("Copy SSH Config Include Line") {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString("Include \"\(viewModel.sshIncludePath)\"", forType: .string)
                            viewModel.globalMessage = "Copied — paste at the top of ~/.ssh/config to route hosts through gateways."
                        }
                    }
                }

                Divider()

                Button("Quit Burrow") {
                    viewModel.quit()
                }
            } label: {
                Label("Settings", systemImage: "gearshape")
                    .font(.system(size: 11))
            }
            .menuStyle(.borderlessButton)
            .fixedSize()

            Spacer()

            Menu {
                Button {
                    viewModel.createTunnel()
                } label: {
                    Label("New SSH Tunnel", systemImage: "arrow.left.arrow.right")
                }
                Button {
                    viewModel.createGateway()
                } label: {
                    Label("New VPN Gateway", systemImage: "lock.shield")
                }
                Button {
                    viewModel.createSSHHost()
                } label: {
                    Label("New SSH Host…", systemImage: "terminal")
                }
                Button {
                    viewModel.createProfile()
                } label: {
                    Label("New Profile", systemImage: "square.stack")
                }
            } label: {
                Label("New", systemImage: "plus")
            }
            .menuStyle(.button)
            .buttonStyle(.borderedProminent)
            .tint(.burrowPrimaryButton)
            .fixedSize()
        }
        .controlSize(.small)
    }

    /// One-click scenes: each chip starts/stops its profile; dot shows state.
    private var profileChipsRow: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 6) {
                ForEach(viewModel.profiles) { profile in
                    ProfileChip(
                        name: profile.name,
                        state: viewModel.profileRunState(profile),
                        onStart: { viewModel.startProfile(named: profile.name) },
                        onStop: { viewModel.stopProfile(named: profile.name) },
                        onToggle: { viewModel.toggleProfile(named: profile.name) },
                        onEdit: { viewModel.openProfileEditor(for: profile.name) },
                        onDelete: { viewModel.deleteProfile(named: profile.name) }
                    )
                }
                // Ghost chip: quick path to another profile.
                Button(action: { viewModel.createProfile() }) {
                    Image(systemName: "plus")
                        .font(.system(size: 9, weight: .bold))
                        .foregroundStyle(.secondary.opacity(0.6))
                        .frame(width: 24, height: 24)
                        .background(
                            Capsule(style: .continuous)
                                .strokeBorder(Color.primary.opacity(0.12), style: StrokeStyle(lineWidth: 1, dash: [3, 2.5]))
                        )
                }
                .buttonStyle(.plain)
                .help("New profile")
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 7)
        }
    }

    private var gatewaysSection: some View {
        VStack(alignment: .leading, spacing: 5) {
            HStack(spacing: 8) {
                Image(systemName: "lock.shield")
                    .font(.system(size: 8, weight: .semibold))
                    .foregroundStyle(.secondary.opacity(0.64))
                    .frame(width: 17, height: 17)
                    .background(
                        RoundedRectangle(cornerRadius: 6, style: .continuous)
                            .fill(Color.secondary.opacity(0.055))
                    )
                Text(verbatim: "VPN Gateways")
                    .font(.system(size: 10, weight: .bold))
                    .tracking(0.15)
                    .foregroundStyle(Color.secondary.opacity(0.62))
                Spacer(minLength: 4)
                Button {
                    viewModel.createGateway()
                } label: {
                    Image(systemName: "plus")
                        .font(.system(size: 9, weight: .bold))
                        .foregroundStyle(.secondary.opacity(0.7))
                        .frame(width: 17, height: 17)
                        .background(
                            RoundedRectangle(cornerRadius: 6, style: .continuous)
                                .fill(Color.secondary.opacity(0.055))
                        )
                }
                .buttonStyle(.plain)
                .help("New VPN gateway")
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 1)

            VStack(alignment: .leading, spacing: 0) {
                ForEach(Array(viewModel.gateways.enumerated()), id: \.element.id) { index, gateway in
                    if index > 0 {
                        Divider()
                            .opacity(0.34)
                            .padding(.leading, 42)
                    }
                    GatewayRow(
                        gateway: gateway,
                        onStart: { viewModel.startGateway(named: gateway.id) },
                        onStop: { viewModel.stopGateway(named: gateway.id) },
                        onEdit: { viewModel.openGatewayEditor(for: gateway.id) },
                        onDelete: { viewModel.deleteGateway(named: gateway.id) },
                        onOpenBrowser: { viewModel.openBrowser($0, viaGateway: gateway.id) }
                    )
                }
            }
            .background(
                RoundedRectangle(cornerRadius: 16, style: .continuous)
                    .fill(Color(nsColor: .controlBackgroundColor).opacity(0.54))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 16, style: .continuous)
                    .stroke(Color.primary.opacity(0.06), lineWidth: 1)
            )
            .shadow(color: Color.black.opacity(0.045), radius: 6, x: 0, y: 3)
        }
    }

    private var hostsSection: some View {
        // Collapsed by default — a quiet drawer of ssh-config login targets.
        let expanded = viewModel.isSectionExpanded("hosts", defaultExpanded: false)
        return VStack(alignment: .leading, spacing: 5) {
            Button {
                viewModel.toggleSection("hosts")
            } label: {
                HStack(spacing: 8) {
                    Image(systemName: "chevron.right")
                        .font(.system(size: 9, weight: .bold))
                        .foregroundStyle(.secondary.opacity(0.6))
                        .rotationEffect(.degrees(expanded ? 90 : 0))
                        .frame(width: 14, height: 17)
                    Text(verbatim: "SSH Hosts")
                        .font(.system(size: 10, weight: .bold))
                        .tracking(0.15)
                        .foregroundStyle(Color.secondary.opacity(0.62))
                    Text(verbatim: "\(viewModel.sshHostEntries.count) · ~/.ssh/config")
                        .font(.system(size: 9))
                        .foregroundStyle(Color.secondary.opacity(0.45))
                    Spacer(minLength: 4)
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 1)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)

            if expanded {
                VStack(alignment: .leading, spacing: 0) {
                    ForEach(Array(viewModel.sshHostEntries.enumerated()), id: \.element.alias) { index, host in
                        if index > 0 {
                            Divider()
                                .opacity(0.34)
                                .padding(.leading, 42)
                        }
                        SSHHostRow(
                            host: host,
                            onOpen: { viewModel.openSSHHost(alias: host.alias) },
                            onCopy: { viewModel.copySSHHostCommand(alias: host.alias) }
                        )
                    }
                }
                .background(
                    RoundedRectangle(cornerRadius: 16, style: .continuous)
                        .fill(Color(nsColor: .controlBackgroundColor).opacity(0.54))
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 16, style: .continuous)
                        .stroke(Color.primary.opacity(0.06), lineWidth: 1)
                )
                .shadow(color: Color.black.opacity(0.045), radius: 6, x: 0, y: 3)
            }
        }
    }

    private var importCandidatesBinding: Binding<[SSHConfigImportCandidate]> {
        Binding(
            get: { viewModel.importCandidates ?? [] },
            set: { viewModel.importCandidates = $0 }
        )
    }

    private var endpointGroups: [EndpointGroup] {
        var groups: [EndpointGroup] = []

        for tunnel in viewModel.tunnels {
            let displayGroup = tunnel.tunnel.displayGroup?.trimmingCharacters(in: .whitespacesAndNewlines)
            let endpoint = displayGroup?.isEmpty == false ? displayGroup! : tunnel.tunnel.host
            if let index = groups.firstIndex(where: { $0.endpoint == endpoint }) {
                var tunnels = groups[index].tunnels
                tunnels.append(tunnel)
                groups[index] = EndpointGroup(
                    endpoint: endpoint,
                    hostForNewTunnel: groups[index].hostForNewTunnel,
                    tunnels: tunnels
                )
            } else {
                groups.append(EndpointGroup(
                    endpoint: endpoint,
                    hostForNewTunnel: tunnel.tunnel.host,
                    tunnels: [tunnel]
                ))
            }
        }

        return groups
    }
}

/// A plain ssh login target from ~/.ssh/config — no forwards, no supervision.
/// Whole-row click opens the session; the menu also offers copy.
private struct SSHHostRow: View {
    let host: SSHConfigHost
    let onOpen: () -> Void
    let onCopy: () -> Void

    @State private var hovering = false

    private var subtitle: String {
        var text = host.user.map { "\($0)@\(host.effectiveHost)" } ?? host.effectiveHost
        if let port = host.port, port != 22 {
            text += ":\(port)"
        }
        return text
    }

    var body: some View {
        Button(action: onOpen) {
            HStack(spacing: 12) {
                Image(systemName: "terminal")
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary.opacity(0.7))
                    .frame(width: 22)
                VStack(alignment: .leading, spacing: 1) {
                    Text(host.alias)
                        .font(.system(size: 13, weight: .semibold))
                        .lineLimit(1)
                    Text(subtitle)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                Spacer(minLength: 8)
                if hovering {
                    Image(systemName: "arrow.up.forward.app")
                        .font(.system(size: 11))
                        .foregroundStyle(Color.burrowAccent)
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 9)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help("Open ssh \(host.alias) in a terminal")
        .onHover { hovering = $0 }
        .contextMenu {
            Button("Open SSH in Terminal", action: onOpen)
            Button("Copy SSH Command", action: onCopy)
        }
    }
}

private struct EndpointHeader: View {
    let group: MenuBarContent.EndpointGroup
    let gatewayNames: [String]
    var isExpanded: Bool = true
    var onToggleCollapse: () -> Void = {}
    let onSelectGateway: (String?) -> Void
    var onAddTunnel: () -> Void = {}

    var body: some View {
        HStack(spacing: 8) {
            Button(action: onToggleCollapse) {
                Image(systemName: "chevron.right")
                    .font(.system(size: 9, weight: .bold))
                    .foregroundStyle(.secondary.opacity(0.6))
                    .rotationEffect(.degrees(isExpanded ? 90 : 0))
                    .frame(width: 14, height: 17)
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .help(isExpanded ? "Collapse" : "Expand")
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
            if !gatewayNames.isEmpty {
                gatewayPickerChip
            }
            Spacer(minLength: 4)
            EndpointHealthDots(tunnels: group.tunnels)
            Button(action: onAddTunnel) {
                Image(systemName: "plus")
                    .font(.system(size: 9, weight: .bold))
                    .foregroundStyle(.secondary.opacity(0.7))
                    .frame(width: 17, height: 17)
                    .background(
                        RoundedRectangle(cornerRadius: 6, style: .continuous)
                            .fill(Color.secondary.opacity(0.055))
                    )
            }
            .buttonStyle(.plain)
            .help("New tunnel to \(group.endpoint) — prefilled from this host")
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 1)
        .help(group.endpoint)
    }

    /// "" = direct, a name = that gateway, nil = tunnels in this group differ.
    private var uniformGatewaySelection: String? {
        let values = Set(group.tunnels.map { $0.tunnel.gateway ?? "" })
        return values.count == 1 ? values.first : nil
    }

    private var gatewayPickerChip: some View {
        Menu {
            Picker("Route this host", selection: Binding(
                get: { uniformGatewaySelection ?? "__mixed__" },
                set: { selected in
                    onSelectGateway(selected.isEmpty ? nil : selected)
                }
            )) {
                Text("Direct (No VPN)").tag("")
                ForEach(gatewayNames, id: \.self) { name in
                    Text("Via \(name)").tag(name)
                }
            }
            .pickerStyle(.inline)
            .labelsHidden()
        } label: {
            HStack(spacing: 3) {
                Image(systemName: "lock.shield")
                    .font(.system(size: 7.5, weight: .semibold))
                Text(verbatim: chipLabel)
                    .font(.system(size: 9.5, weight: .bold, design: .monospaced))
                    .lineLimit(1)
                Image(systemName: "chevron.down")
                    .font(.system(size: 6, weight: .bold))
            }
            .foregroundStyle(chipIsActive ? Color.burrowAccent.opacity(0.9) : Color.secondary.opacity(0.62))
            .padding(.horizontal, 7)
            .frame(height: 18)
            .background(
                Capsule(style: .continuous)
                    .fill(chipIsActive ? Color.burrowAccentHalo.opacity(0.7) : Color.secondary.opacity(0.055))
            )
        }
        .menuStyle(.borderlessButton)
        .menuIndicator(.hidden)
        .fixedSize()
        .help("Which VPN gateway tunnels to this host connect through")
    }

    private var chipLabel: String {
        switch uniformGatewaySelection {
        case .some(""):
            return "direct"
        case .some(let name):
            return name
        case nil:
            return "mixed"
        }
    }

    private var chipIsActive: Bool {
        if let selection = uniformGatewaySelection, !selection.isEmpty {
            return true
        }
        return false
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
            if upCount > 0 {
                summaryBadge(count: upCount, color: .green)
            }
            if connectingCount > 0 {
                summaryBadge(count: connectingCount, color: .orange)
            }
            if failedCount > 0 {
                summaryBadge(count: failedCount, color: .red)
            }
            if upCount == 0 && connectingCount == 0 && failedCount == 0 {
                summaryBadge(count: waitingCount, color: .gray)
            }
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

private struct ProfileChip: View {
    let name: String
    let state: MenuBarViewModel.ProfileRunState
    let onStart: () -> Void
    let onStop: () -> Void
    let onToggle: () -> Void
    let onEdit: () -> Void
    let onDelete: () -> Void
    @State private var isHovered = false

    var body: some View {
        Button(action: onToggle) {
            HStack(spacing: 5) {
                Circle()
                    .fill(dotColor)
                    .frame(width: 5.5, height: 5.5)
                Text(name)
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(.primary.opacity(0.82))
                    .lineLimit(1)
            }
            .padding(.horizontal, 10)
            .frame(height: 24)
            .background(
                Capsule(style: .continuous)
                    .fill(state == .up ? Color.green.opacity(isHovered ? 0.16 : 0.10) : Color.secondary.opacity(isHovered ? 0.12 : 0.07))
            )
            .overlay(
                Capsule(style: .continuous)
                    .stroke(state == .up ? Color.green.opacity(0.25) : Color.primary.opacity(0.08), lineWidth: 1)
            )
        }
        .buttonStyle(CompactPressButtonStyle())
        .onHover { hovering in
            withAnimation(.easeOut(duration: 0.1)) {
                isHovered = hovering
            }
        }
        .help(helpText)
        .contextMenu {
            Button("Start", action: onStart)
            Button("Stop", action: onStop)
            Divider()
            Button("Edit…", action: onEdit)
            Divider()
            Button("Delete", role: .destructive, action: onDelete)
        }
    }

    private var dotColor: Color {
        switch state {
        case .up: return .green
        case .partial: return .orange
        case .down: return Color(nsColor: .tertiaryLabelColor)
        }
    }

    private var helpText: String {
        switch state {
        case .up: return "Profile \(name): all up — click to stop"
        case .partial: return "Profile \(name): partially up — click to stop"
        case .down: return "Profile \(name): click to start"
        }
    }
}

private struct GatewayRow: View {
    let gateway: MenuBarViewModel.GatewayState
    let onStart: () -> Void
    let onStop: () -> Void
    let onEdit: () -> Void
    let onDelete: () -> Void
    var onOpenBrowser: (ChromiumBrowser) -> Void = { _ in }
    @State private var isPrimaryHovered = false

    var body: some View {
        HStack(alignment: .center, spacing: 10) {
            ZStack {
                Circle()
                    .fill(statusColor.opacity(0.10))
                    .frame(width: 18, height: 18)
                Circle()
                    .fill(statusColor)
                    .frame(width: 8, height: 8)
            }

            VStack(alignment: .leading, spacing: 4) {
                Text(gateway.config.name)
                    .font(.system(size: 13.4, weight: .bold))
                    .foregroundStyle(.primary.opacity(0.92))
                    .lineLimit(1)
                    .truncationMode(.middle)
                if gateway.connectionState == .failed {
                    Text(verbatim: gateway.lastMessage)
                        .font(.system(size: 11.2, weight: .medium, design: .monospaced))
                        .foregroundStyle(Color.burrowFailure.opacity(0.9))
                        .lineLimit(1)
                        .truncationMode(.tail)
                } else {
                    Text(verbatim: "\(gateway.config.server) · socks :\(String(gateway.config.socksPort))")
                        .font(.system(size: 11.2, weight: .medium, design: .monospaced))
                        .monospacedDigit()
                        .foregroundStyle(.secondary.opacity(0.95))
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
            }
            .layoutPriority(1)
            .help(GatewayCommandBuilder.render(gateway.config))

            Spacer(minLength: 6)

            HStack(spacing: 5) {
                primaryButton
                menu
            }
            .frame(width: 100, alignment: .trailing)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
    }

    @ViewBuilder
    private var primaryButton: some View {
        if gateway.isRunning {
            Button(action: onStop) {
                Text("Stop")
                    .font(.system(size: 11, weight: .bold))
                    .frame(width: 68, height: 28)
                    .foregroundStyle(isPrimaryHovered ? Color.burrowFailure : Color.primary.opacity(0.82))
                    .background(
                        Capsule(style: .continuous)
                            .fill(isPrimaryHovered ? Color.red.opacity(0.10) : Color(nsColor: .windowBackgroundColor))
                    )
                    .overlay(
                        Capsule(style: .continuous)
                            .stroke(isPrimaryHovered ? Color.burrowFailure.opacity(0.35) : Color.primary.opacity(0.16), lineWidth: 1)
                    )
            }
            .buttonStyle(CompactPressButtonStyle())
            .onHover { hovering in
                withAnimation(.easeOut(duration: 0.12)) {
                    isPrimaryHovered = hovering
                }
            }
        } else {
            Button(action: onStart) {
                Text("Connect")
                    .font(.system(size: 11, weight: .bold))
                    .minimumScaleFactor(0.82)
                    .frame(width: 68, height: 28)
                    .foregroundStyle(.white)
                    .background(
                        Capsule(style: .continuous)
                            .fill(
                                LinearGradient(
                                    colors: [
                                        Color(red: 0.26, green: 0.19, blue: 0.84),
                                        Color(red: 0.19, green: 0.42, blue: 0.94),
                                    ],
                                    startPoint: .leading,
                                    endPoint: .trailing
                                )
                            )
                    )
            }
            .buttonStyle(CompactPressButtonStyle())
        }
    }

    private var menu: some View {
        Menu {
            Button("Edit…", action: onEdit)
            let browsers = ChromiumBrowserLauncher.installed()
            if !browsers.isEmpty {
                Divider()
                ForEach(browsers) { browser in
                    Button("Open \(browser.displayName) via VPN") {
                        onOpenBrowser(browser)
                    }
                }
            }
            Divider()
            Button("Copy SSH Command Template") {
                copy("ssh -o ProxyCommand='\(GatewayLinker.proxyCommand(for: gateway.config))' USER@HOST")
            }
            Button("Copy SOCKS Address") {
                copy("127.0.0.1:\(gateway.config.socksPort)")
            }
            Button("Copy SSH ProxyCommand Option") {
                copy("-o ProxyCommand='\(GatewayLinker.proxyCommand(for: gateway.config))'")
            }
            Button("Copy OpenConnect Command") {
                copy(GatewayCommandBuilder.render(gateway.config))
            }
            Divider()
            Button("Delete", role: .destructive, action: onDelete)
        } label: {
            Image(systemName: "ellipsis")
                .font(.system(size: 11.5, weight: .heavy))
                .foregroundStyle(Color.secondary.opacity(0.60))
                .frame(width: 20, height: 28)
        }
        .menuStyle(.borderlessButton)
        .menuIndicator(.hidden)
        .frame(width: 20, height: 28, alignment: .trailing)
    }

    private var statusColor: Color {
        switch gateway.connectionState {
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

    private func copy(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }
}

struct TunnelRow: View {
    let tunnel: MenuBarViewModel.TunnelState
    var gatewayNames: [String] = []
    let onStart: () -> Void
    let onStop: () -> Void
    let onRestart: () -> Void
    let onEdit: () -> Void
    let onDuplicate: () -> Void
    let onDelete: () -> Void
    let onToggleAutoConnect: (Bool) -> Void
    var onSetGateway: (String?) -> Void = { _ in }
    var onOpenSSH: () -> Void = {}
    var onCopySSH: () -> Void = {}
    @State private var isIdentityTooltipVisible = false
    @State private var isDetailsPresented = false
    @State private var isAutoHovered = false
    @State private var isPrimaryHovered = false
    @State private var isMenuHovered = false
    @State private var identityHoverTask: Task<Void, Never>?

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

                if tunnel.connectionState == .failed {
                    failureStatusView
                } else {
                    routeWithSSHSuffix
                }
            }
            .layoutPriority(1)
            .contentShape(Rectangle())
            .onHover { hovering in
                identityHoverTask?.cancel()
                if hovering {
                    identityHoverTask = Task { @MainActor in
                        try? await Task.sleep(for: .milliseconds(500))
                        guard !Task.isCancelled else { return }
                        withAnimation(.easeInOut(duration: 0.08)) {
                            isIdentityTooltipVisible = true
                        }
                    }
                } else {
                    withAnimation(.easeInOut(duration: 0.08)) {
                        isIdentityTooltipVisible = false
                    }
                }
            }
            .popover(isPresented: $isIdentityTooltipVisible, arrowEdge: .top) {
                identityTooltip
            }

            Spacer(minLength: 6)

            HStack(spacing: 5) {
                autoConnectButton
                primaryActionButton
                rowMenu
            }
            .frame(width: 134, alignment: .trailing)
            .layoutPriority(2)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
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
            if let presentation = failurePresentation {
                Divider()
                Text(presentation.codeLine)
                    .font(.system(size: 10.5, weight: .semibold, design: .monospaced))
                    .foregroundStyle(presentation.color)
                Text(presentation.hintLine)
                    .font(.system(size: 10.5))
                    .foregroundStyle(.secondary)
                    .lineLimit(3)
            }
        }
        .padding(.horizontal, 11)
        .padding(.vertical, 9)
        .frame(maxWidth: 330, alignment: .leading)
    }

    /// How long a stopped tunnel keeps showing its failure diagnosis before the
    /// row reverts to the route; the diagnosis stays in the hover card and Details.
    private static let failureDisplayWindow: TimeInterval = 60

    private var routeWithSSHSuffix: some View {
        HStack(spacing: 7) {
            if let chipForward = leadingChipForward {
                CopyPortChip(label: String(chipForward.listenPort), address: localAddress(for: chipForward))
            }
            routeDetailText
                .lineLimit(1)
                .truncationMode(.tail)
        }
        .help(fullRouteSummary)
    }

    /// The single-forward listen port renders as the copyable chip.
    private var leadingChipForward: ForwardSpec? {
        guard tunnel.tunnel.forwards.count == 1,
              let forward = tunnel.tunnel.forwards.first,
              forward.kind != .remote else {
            return nil
        }
        return forward
    }

    /// The whole detail line as ONE Text so tail truncation trims the
    /// least-important trailing parts first. Separate views compress equally
    /// under width pressure, which used to truncate even the destination into
    /// "…" while suffixes survived.
    private var routeDetailText: Text {
        let routeFont = Font.system(size: 11.2, weight: .medium, design: .monospaced)
        let suffixFont = Font.system(size: 10, weight: .medium, design: .monospaced)
        let routeColor = Color.secondary.opacity(0.95)
        let suffixColor = Color.secondary.opacity(0.45)

        var text: Text
        if tunnel.tunnel.forwards.count == 1, let forward = tunnel.tunnel.forwards.first {
            switch forward.kind {
            case .local:
                text = Text(verbatim: "› \(compactDestinationText(for: forward))")
                    .font(routeFont).foregroundColor(routeColor)
            case .dynamic:
                text = Text(verbatim: "· SOCKS")
                    .font(routeFont).foregroundColor(routeColor)
            case .remote:
                text = Text(verbatim: "\(compactDestinationText(for: forward)) ‹ \(String(forward.listenPort))")
                    .font(routeFont).foregroundColor(routeColor)
            }
        } else {
            text = Text(verbatim: compactRouteSummary)
                .font(routeFont).foregroundColor(routeColor)
        }

        if tunnel.connectionState == .connected, case .unreachable = tunnel.serviceReachable {
            text = text + Text(verbatim: "  ·  service down")
                .font(.system(size: 10, weight: .semibold, design: .monospaced))
                .foregroundColor(.orange.opacity(0.9))
        }
        if let gatewayName = tunnel.tunnel.gateway {
            text = text + Text(verbatim: "  ·  via \(gatewayName)")
                .font(suffixFont).foregroundColor(suffixColor)
        }
        if tunnel.tunnel.sshPort != 22 {
            text = text + Text(verbatim: "  ·  ssh :\(String(tunnel.tunnel.sshPort))")
                .font(suffixFont).foregroundColor(suffixColor)
        }
        return text
    }

    private var failureStatusView: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            if shouldShowFailureStatus(at: context.date) {
                Text(verbatim: failureStatusText(at: context.date))
                    .font(.system(size: 11.2, weight: .medium, design: .monospaced))
                    .monospacedDigit()
                    .foregroundStyle(Color.burrowFailure.opacity(0.9))
                    .lineLimit(1)
                    .truncationMode(.tail)
            } else {
                routeWithSSHSuffix
            }
        }
    }

    private func shouldShowFailureStatus(at date: Date) -> Bool {
        if tunnel.isRunning {
            return true
        }
        guard let failedAt = tunnel.failedAt else {
            return false
        }
        return date.timeIntervalSince(failedAt) < Self.failureDisplayWindow
    }

    private func failureStatusText(at date: Date) -> String {
        let category = failurePresentation?.category ?? "failed"

        if tunnel.isRunning, let nextRetryAt = tunnel.nextRetryAt {
            let remaining = max(0, Int(nextRetryAt.timeIntervalSince(date).rounded(.up)))
            let attemptText = tunnel.retryAttempt > 1 ? "retry \(tunnel.retryAttempt)" : "retry"
            return remaining > 0 ? "\(category) · \(attemptText) in \(remaining)s" : "\(category) · retrying now"
        }
        if tunnel.isRunning {
            return "\(category) · retrying"
        }

        let detail = failurePresentation?.codeLine ?? "connection failed"
        return detail.lowercased() == category.lowercased() ? category : detail
    }

    private func localAddress(for forward: ForwardSpec) -> String {
        let bind = forward.bindAddress?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let host = bind.isEmpty || isLoopbackHost(bind) || bind == "*" || bind == "0.0.0.0" ? "localhost" : bind
        return "\(host):\(forward.listenPort)"
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
            if !copyableForwards.isEmpty {
                Divider()
                ForEach(Array(copyableForwards.enumerated()), id: \.offset) { _, forward in
                    Button("Copy “\(localAddress(for: forward))”") {
                        copyToPasteboard(localAddress(for: forward))
                    }
                }
                ForEach(Array(browsableForwards.enumerated()), id: \.offset) { _, forward in
                    Button("Open “\(localAddress(for: forward))” in Browser") {
                        if let url = URL(string: "http://\(localAddress(for: forward))") {
                            NSWorkspace.shared.open(url)
                        }
                    }
                }
            }
            if tunnel.isRunning && tunnel.connectionState == .failed {
                Divider()
                Button("Stop Retrying", action: onStop)
            }
            if !gatewayNames.isEmpty {
                Divider()
                Picker("Gateway", selection: Binding(
                    get: { tunnel.tunnel.gateway ?? "" },
                    set: { onSetGateway($0.isEmpty ? nil : $0) }
                )) {
                    Text("Direct (No VPN)").tag("")
                    ForEach(gatewayNames, id: \.self) { name in
                        Text("Via \(name)").tag(name)
                    }
                }
            }
            Divider()
            Button("Open SSH in Terminal", action: onOpenSSH)
            Button("Copy SSH Command", action: onCopySSH)
            Divider()
            Button("Restart", action: onRestart)
            Button("Edit…", action: onEdit)
            Button("Duplicate…", action: onDuplicate)
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
            Image(systemName: "bolt.fill")
                .font(.system(size: 12, weight: .semibold))
                .foregroundStyle(
                    tunnel.isConfiguredEnabled
                        ? Color.burrowAccent
                        : Color.secondary.opacity(isAutoHovered ? 0.55 : 0.30)
                )
                .frame(width: 28, height: 28)
                .background(
                    Circle()
                        .fill(
                            tunnel.isConfiguredEnabled
                                ? Color.burrowAccentHalo.opacity(isAutoHovered ? 1.0 : 0.75)
                                : Color.secondary.opacity(isAutoHovered ? 0.09 : 0.0)
                        )
                )
                .scaleEffect(isAutoHovered ? 1.05 : 1.0)
        }
        .buttonStyle(CompactPressButtonStyle())
        .onHover { hovering in
            withAnimation(.easeOut(duration: 0.12)) {
                isAutoHovered = hovering
            }
        }
        .frame(width: 28, height: 28)
        .help(tunnel.isConfiguredEnabled ? "Auto-connect on — click to turn off" : "Auto-connect off — click to turn on")
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
                    .foregroundStyle(isPrimaryHovered ? Color.burrowFailure : Color.primary.opacity(0.82))
                    .background(
                        Capsule(style: .continuous)
                            .fill(isPrimaryHovered ? Color.red.opacity(0.10) : Color(nsColor: .windowBackgroundColor))
                    )
                    .overlay(
                        Capsule(style: .continuous)
                            .stroke(isPrimaryHovered ? Color.burrowFailure.opacity(0.35) : Color.primary.opacity(0.16), lineWidth: 1)
                    )
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

    private var failurePresentation: TunnelFailurePresentation? {
        TunnelFailureClassifier.presentation(for: tunnel)
    }

    private var sshCommandText: String {
        let prepared = (try? TunnelLaunchPreparer.prepare(tunnel.tunnel)) ?? tunnel.tunnel
        return SSHCommandBuilder.render(prepared)
    }

    private var copyableForwards: [ForwardSpec] {
        tunnel.tunnel.forwards.filter { $0.kind != .remote }
    }

    private var browsableForwards: [ForwardSpec] {
        tunnel.tunnel.forwards.filter { $0.kind == .local }
    }

    private func copyToPasteboard(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }
}

private struct CopyPortChip: View {
    let label: String
    let address: String
    @State private var showCopied = false
    @State private var revertTask: Task<Void, Never>?
    @State private var isHovered = false

    var body: some View {
        Button {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(address, forType: .string)
            revertTask?.cancel()
            showCopied = true
            revertTask = Task { @MainActor in
                try? await Task.sleep(for: .milliseconds(1100))
                guard !Task.isCancelled else { return }
                showCopied = false
            }
        } label: {
            HStack(spacing: 3) {
                if showCopied {
                    Image(systemName: "checkmark")
                        .font(.system(size: 8, weight: .bold))
                        .foregroundStyle(.green)
                } else if isHovered {
                    Image(systemName: "doc.on.doc")
                        .font(.system(size: 8, weight: .semibold))
                        .foregroundStyle(.secondary.opacity(0.7))
                }
                Text(verbatim: label)
                    .font(.system(size: 11.2, weight: .bold, design: .monospaced))
                    .monospacedDigit()
                    .foregroundStyle(showCopied ? Color.green.opacity(0.9) : Color.secondary.opacity(0.95))
            }
            .lineLimit(1)
            .fixedSize(horizontal: true, vertical: false)
            .padding(.horizontal, 6)
            .frame(height: 21)
            .background(
                RoundedRectangle(cornerRadius: 5, style: .continuous)
                    .fill(showCopied ? Color.green.opacity(0.12) : Color.secondary.opacity(isHovered ? 0.12 : 0.065))
            )
        }
        .buttonStyle(.plain)
        .onHover { hovering in
            withAnimation(.easeOut(duration: 0.1)) {
                isHovered = hovering
            }
        }
        .help("Copy \(address)")
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
            switch tunnel.serviceReachable {
            case .reachable: return "service reachable"
            case .unreachable: return "tunnel up, service not responding"
            case .unknown: return "local forward reachable"
            }
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
                color: .burrowFailure
            )
        }

        if containsAny(lowercased, ["address already in use", "cannot listen to port", "could not request local forwarding"]) {
            return TunnelFailurePresentation(
                category: "port conflict",
                codeLine: "local port unavailable",
                hintLine: "Another process is already listening on this local port.",
                color: .burrowFailure
            )
        }

        if containsAny(lowercased, ["could not resolve hostname", "nodename nor servname", "temporary failure in name resolution"]) {
            return TunnelFailurePresentation(
                category: "dns issue",
                codeLine: "host not resolvable",
                hintLine: "Check VPN, DNS, or the current network environment.",
                color: .burrowFailure
            )
        }

        if containsAny(lowercased, ["operation timed out", "connection timed out", "network is unreachable", "no route to host", "connection refused", "connection closed", "connection reset", "broken pipe"]) {
            return TunnelFailurePresentation(
                category: "network issue",
                codeLine: "network unavailable",
                hintLine: "Check VPN, remote reachability, or firewall rules.",
                color: .burrowFailure
            )
        }

        if containsAny(lowercased, ["host key verification failed", "remote host identification has changed"]) {
            return TunnelFailurePresentation(
                category: "host key issue",
                codeLine: "host key rejected",
                hintLine: "Review the known-hosts entry for this endpoint.",
                color: .burrowFailure
            )
        }

        if lowercased.contains("255") {
            return TunnelFailurePresentation(
                category: "ssh exited",
                codeLine: "ssh exited 255",
                hintLine: "Usually VPN, DNS, host reachability, or SSH policy.",
                color: .burrowFailure
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
            color: .burrowFailure
        )
    }

    private static func containsAny(_ text: String, _ needles: [String]) -> Bool {
        needles.contains { text.contains($0) }
    }
}

struct TunnelEditorSuggestions {
    let tunnels: [TunnelConfig]
    let sshHosts: [SSHConfigHost]
    var gatewayNames: [String] = []
    let hosts: [String]
    let users: [String]
    let sshPorts: [String]
    let identityFiles: [String]
    let jumpHosts: [String]
    let bindAddresses: [String]
    let destinationHosts: [String]
    let destinationPorts: [String]
    let nextAvailableLocalPort: Int

    init(tunnels: [TunnelConfig], sshHosts: [SSHConfigHost] = [], gatewayNames: [String] = []) {
        self.tunnels = tunnels
        self.sshHosts = sshHosts
        self.gatewayNames = gatewayNames
        self.hosts = Self.ranked(
            tunnels.map(\.host),
            appending: sshHosts.map(\.alias) + sshHosts.compactMap(\.hostName)
        )
        self.users = Self.ranked(
            tunnels.compactMap(\.user),
            appending: sshHosts.compactMap(\.user) + [NSUserName()]
        )
        self.sshPorts = Self.ranked(
            tunnels.map { String($0.sshPort) },
            appending: sshHosts.compactMap { $0.port.map(String.init) } + ["22"]
        )
        self.identityFiles = Self.ranked(
            tunnels.compactMap(\.identityFile),
            appending: sshHosts.compactMap(\.identityFile) + Self.commonIdentityFiles()
        )
        self.jumpHosts = Self.ranked(
            tunnels.compactMap(\.jumpHost),
            appending: sshHosts.compactMap(\.proxyJump)
        )

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
        let fromTunnels = Self.ranked(
            tunnels
                .filter { normalized($0.host) == normalizedHost }
                .map { String($0.sshPort) }
        )
        .first
        return fromTunnels ?? sshHostMatch(host)?.port.map(String.init)
    }

    private func sshHostMatch(_ host: String) -> SSHConfigHost? {
        let normalizedHost = normalized(host)
        guard !normalizedHost.isEmpty else {
            return nil
        }
        return sshHosts.first {
            normalized($0.alias) == normalizedHost || normalized($0.effectiveHost) == normalizedHost
        }
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

        let fromTunnels = Self.ranked(
            tunnels
                .filter { normalized($0.host) == normalizedHost }
                .compactMap(\.user)
        )
        .first
        return fromTunnels ?? sshHostMatch(host)?.user
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

        let fromTunnels = Self.ranked(
            tunnels
                .filter { normalized($0.host) == normalizedHost }
                .compactMap(\.identityFile)
        )
        .first
        return fromTunnels ?? sshHostMatch(host)?.identityFile
    }

    func preferredJumpHost(for host: String) -> String? {
        let normalizedHost = normalized(host)
        let fromTunnels = Self.ranked(
            tunnels
                .filter { normalized($0.host) == normalizedHost }
                .compactMap(\.jumpHost)
        )
        .first
        return fromTunnels ?? sshHostMatch(host)?.proxyJump
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

        var seen = Set(rankedValues.map { $0.lowercased() })
        var appendedDefaults: [String] = []
        for defaultValue in defaults {
            let trimmed = defaultValue.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty, seen.insert(trimmed.lowercased()).inserted else {
                continue
            }
            appendedDefaults.append(trimmed)
        }
        return rankedValues + appendedDefaults
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
    var gateway: String
    var onConnect: String
    var onDisconnect: String

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
        self.gateway = tunnel.gateway ?? ""
        self.onConnect = tunnel.onConnect ?? ""
        self.onDisconnect = tunnel.onDisconnect ?? ""
    }

    static func newTunnel(from existingTunnels: [TunnelConfig] = [], sshHosts: [SSHConfigHost] = []) -> TunnelDraft {
        let suggestions = TunnelEditorSuggestions(tunnels: existingTunnels, sshHosts: sshHosts)
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
            extraSSHOptions: sshOptions,
            gateway: gateway.nonEmptyValue,
            onConnect: onConnect.nonEmptyValue,
            onDisconnect: onDisconnect.nonEmptyValue
        )
    }
}

struct TunnelEditorSheet: View {
    @Binding var draft: TunnelDraft
    let suggestions: TunnelEditorSuggestions
    var conflictChecker: PortConflictChecker?
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
                if !suggestions.gatewayNames.isEmpty {
                    GridRow {
                        editorLabel("Gateway")
                        HStack(spacing: 8) {
                            Picker("Gateway", selection: $draft.gateway) {
                                Text("None").tag("")
                                ForEach(suggestions.gatewayNames, id: \.self) { name in
                                    Text(name).tag(name)
                                }
                            }
                            .labelsHidden()
                            .controlSize(.small)
                            .frame(width: 160)
                            .help("Route this tunnel's ssh connection through a Burrow VPN gateway")
                            Spacer()
                        }
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
                    conflictChecker: conflictChecker,
                    otherListenPorts: draft.forwards
                        .filter { $0.id != forward.id && $0.kind != .remote }
                        .compactMap { Int($0.listenPort) },
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

                VStack(alignment: .leading, spacing: 5) {
                    Text("Hooks")
                        .font(.system(size: 10.5, weight: .semibold))
                        .foregroundStyle(.secondary)
                    Text("Shell commands run on connect / disconnect. Env: $BURROW_TUNNEL, $BURROW_LOCAL_PORT, $BURROW_HOST.")
                        .font(.system(size: 10))
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                    Grid(alignment: .leading, horizontalSpacing: 10, verticalSpacing: 6) {
                        GridRow {
                            editorLabel("On Connect")
                            TextField("e.g. open http://localhost:$BURROW_LOCAL_PORT", text: $draft.onConnect)
                                .textFieldStyle(.roundedBorder)
                                .font(.system(size: 11, design: .monospaced))
                        }
                        GridRow {
                            editorLabel("On Disconnect")
                            TextField("e.g. umount ~/mnt/$BURROW_TUNNEL", text: $draft.onDisconnect)
                                .textFieldStyle(.roundedBorder)
                                .font(.system(size: 11, design: .monospaced))
                        }
                    }
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
                .stroke(Color.primary.opacity(0.06), lineWidth: 1)
        )
    }
}

private struct ForwardEditorCard: View {
    @Binding var forward: TunnelDraft.ForwardDraft
    let suggestions: TunnelEditorSuggestions
    var conflictChecker: PortConflictChecker?
    var otherListenPorts: [Int] = []
    let canRemove: Bool
    let onRemove: () -> Void
    @State private var isAdvancedExpanded = false
    @State private var conflictWarning: String?

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

            if let conflictWarning {
                Label(conflictWarning, systemImage: "exclamationmark.triangle.fill")
                    .font(.system(size: 10.5, weight: .medium))
                    .foregroundStyle(.orange)
                    .lineLimit(2)
            }

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
        .task(id: conflictProbeKey) {
            await refreshConflictWarning()
        }
    }

    private var conflictProbeKey: String {
        "\(forward.kind.rawValue)|\(forward.listenPort)|\(otherListenPorts.map(String.init).joined(separator: ","))"
    }

    private func refreshConflictWarning() async {
        conflictWarning = nil
        guard forward.kind != .remote,
              let checker = conflictChecker,
              let port = Int(forward.listenPort.trimmingCharacters(in: .whitespaces)),
              port > 0 else {
            return
        }

        try? await Task.sleep(for: .milliseconds(300))
        guard !Task.isCancelled else {
            return
        }

        if otherListenPorts.contains(port) {
            conflictWarning = "Another forward in this tunnel already uses port \(port)."
            return
        }
        if let message = checker.savedTunnelConflict(port: port) {
            conflictWarning = message
            return
        }
        guard !checker.portHeldByEditedTunnel(port) else {
            return
        }

        let inUse = await Task.detached { checker.isPortInUseLocally(port) }.value
        if !Task.isCancelled && inUse {
            conflictWarning = "Something is already listening on 127.0.0.1:\(port)."
        }
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
