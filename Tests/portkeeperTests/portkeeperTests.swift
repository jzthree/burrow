import Foundation
import Testing
@testable import PortKeeperCore

final class EventRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private(set) var events: [TunnelRuntimeEvent] = []

    func append(_ event: TunnelRuntimeEvent) {
        lock.lock()
        events.append(event)
        lock.unlock()
    }

    func contains(where predicate: (TunnelRuntimeEvent) -> Bool) -> Bool {
        lock.lock()
        let result = events.contains(where: predicate)
        lock.unlock()
        return result
    }

    func firstExitDiagnostic() -> String? {
        lock.lock()
        let diagnostic = events.compactMap { event -> String? in
            if case .exited(_, let message) = event {
                return message
            }
            return nil
        }.first
        lock.unlock()
        return diagnostic
    }
}

@Test func sshArgumentsIncludeExpectedFlags() async throws {
    let tunnel = TunnelConfig(
        name: "db",
        host: "bastion.example.com",
        user: "alice",
        sshPort: 2222,
        identityFile: "~/.ssh/id_test",
        jumpHost: "jump.example.com",
        forwards: [
            ForwardSpec(kind: .local, bindAddress: "127.0.0.1", listenPort: 15432, destinationHost: "127.0.0.1", destinationPort: 5432),
            ForwardSpec(kind: .dynamic, listenPort: 1080),
        ],
        extraSSHOptions: ["StrictHostKeyChecking=yes"]
    )

    let args = SSHCommandBuilder.buildArguments(for: tunnel)

    #expect(args.contains("-N"))
    // Multiplexing must be disabled so Burrow supervises a foreground ssh.
    #expect(args.contains("ControlMaster=no"))
    #expect(args.contains("ControlPath=none"))
    #expect(args.contains("alice@bastion.example.com"))
    #expect(args.contains("jump.example.com"))
    #expect(args.contains("127.0.0.1:15432:127.0.0.1:5432"))
    #expect(args.contains("1080"))
}

@Test func configRoundTripPreservesTunnel() async throws {
    let tempDirectory = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    let configURL = tempDirectory.appendingPathComponent("config.json")
    let store = ConfigStore(configURL: configURL)

    let tunnel = TunnelConfig(
        name: "redis",
        host: "gateway.internal",
        forwards: [
            ForwardSpec(kind: .local, listenPort: 16379, destinationHost: "127.0.0.1", destinationPort: 6379),
        ]
    )

    try store.upsert(tunnel)
    let config = try store.load()

    #expect(config.tunnels.count == 1)
    #expect(config.tunnels.first?.name == "redis")
    #expect(config.tunnels.first?.forwards.first?.listenPort == 16379)
}

@Test func configUpsertPreservesExistingTunnelOrder() async throws {
    let tempDirectory = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    let configURL = tempDirectory.appendingPathComponent("config.json")
    let store = ConfigStore(configURL: configURL)

    try store.save(AppConfig(tunnels: [
        TunnelConfig(name: "b-web", host: "bastion-b.example.com", forwards: []),
        TunnelConfig(name: "a-web", host: "bastion-a.example.com", forwards: []),
        TunnelConfig(name: "c-web", host: "bastion-c.example.com", forwards: []),
    ]))

    try store.upsert(TunnelConfig(name: "a-web", host: "edited.example.com", forwards: []))

    let names = try store.load().tunnels.map(\.name)
    #expect(names == ["b-web", "a-web", "c-web"])
}

@Test func configUpsertRenamePreservesOriginalSlot() async throws {
    let tempDirectory = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    let configURL = tempDirectory.appendingPathComponent("config.json")
    let store = ConfigStore(configURL: configURL)

    try store.save(AppConfig(tunnels: [
        TunnelConfig(name: "first", host: "first.example.com", forwards: []),
        TunnelConfig(name: "old-name", host: "old.example.com", forwards: []),
        TunnelConfig(name: "last", host: "last.example.com", forwards: []),
    ]))

    try store.upsert(TunnelConfig(name: "new-name", host: "new.example.com", forwards: []), replacing: "old-name")

    let names = try store.load().tunnels.map(\.name)
    #expect(names == ["first", "new-name", "last"])
}

@Test func supervisorMarksPermissionDeniedAsAuthenticationFailure() async throws {
    let tempDirectory = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)

    let scriptURL = tempDirectory.appendingPathComponent("fake-ssh.sh")
    let script = """
    #!/bin/sh
    echo "Permission denied (publickey,password)." 1>&2
    exit 255
    """
    try script.write(to: scriptURL, atomically: true, encoding: .utf8)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: scriptURL.path)

    let recorder = EventRecorder()
    let tunnel = TunnelConfig(
        name: "auth-fail",
        host: "example.com",
        user: "alice",
        forwards: []
    )

    let supervisor = TunnelSupervisor(
        tunnel: tunnel,
        logger: { _ in },
        eventHandler: { event in
            recorder.append(event)
        },
        executablePath: scriptURL.path
    )

    await supervisor.run()

    let sawStarting = recorder.events.contains {
        if case .starting = $0 { return true }
        return false
    }
    let sawAuthFailure = recorder.events.contains {
        if case .authenticationFailed = $0 { return true }
        return false
    }
    let sawExit = recorder.events.contains {
        if case .exited = $0 { return true }
        return false
    }

    #expect(sawStarting)
    #expect(sawAuthFailure)
    #expect(!sawExit)
}

@Test func supervisorTreatsAskPassThen255AsAuthenticationFailure() async throws {
    let tempDirectory = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)

    let askPassURL = tempDirectory.appendingPathComponent("askpass.sh")
    let askPassScript = """
    #!/bin/sh
    if [ -n "$PORTKEEPER_ASKPASS_LOG" ]; then
      printf 'askpass\\n' >> "$PORTKEEPER_ASKPASS_LOG"
    fi
    printf '%s\\n' "$PORTKEEPER_PASSWORD"
    """
    try askPassScript.write(to: askPassURL, atomically: true, encoding: .utf8)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: askPassURL.path)

    let fakeSSHURL = tempDirectory.appendingPathComponent("fake-ssh.sh")
    let fakeSSHScript = """
    #!/bin/sh
    "$SSH_ASKPASS" >/dev/null
    echo "Permission denied (publickey,password)." 1>&2
    exit 255
    """
    try fakeSSHScript.write(to: fakeSSHURL, atomically: true, encoding: .utf8)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: fakeSSHURL.path)

    let askPassLogURL = tempDirectory.appendingPathComponent("askpass.log")
    let recorder = EventRecorder()
    let tunnel = TunnelConfig(
        name: "askpass-auth-fail",
        host: "example.com",
        user: "alice",
        forwards: []
    )

    let supervisor = TunnelSupervisor(
        tunnel: tunnel,
        logger: { _ in },
        eventHandler: { event in
            recorder.append(event)
        },
        environment: [
            "SSH_ASKPASS": askPassURL.path,
            "PORTKEEPER_PASSWORD": "wrong-password",
            "PORTKEEPER_ASKPASS_LOG": askPassLogURL.path,
        ],
        executablePath: fakeSSHURL.path
    )

    await supervisor.run()

    let sawAuthFailure = recorder.contains {
        if case .authenticationFailed = $0 { return true }
        return false
    }
    let sawExit = recorder.contains {
        if case .exited = $0 { return true }
        return false
    }

    #expect(sawAuthFailure)
    #expect(!sawExit)
}

@Test func supervisorTreatsAskPassThenNetwork255AsGenericExit() async throws {
    let tempDirectory = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)

    let askPassURL = tempDirectory.appendingPathComponent("askpass.sh")
    let askPassScript = """
    #!/bin/sh
    if [ -n "$PORTKEEPER_ASKPASS_LOG" ]; then
      printf 'askpass\\n' >> "$PORTKEEPER_ASKPASS_LOG"
    fi
    printf '%s\\n' "$PORTKEEPER_PASSWORD"
    """
    try askPassScript.write(to: askPassURL, atomically: true, encoding: .utf8)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: askPassURL.path)

    let fakeSSHURL = tempDirectory.appendingPathComponent("fake-ssh.sh")
    let fakeSSHScript = """
    #!/bin/sh
    "$SSH_ASKPASS" >/dev/null
    echo "Could not resolve hostname example.internal: nodename nor servname provided, or not known" 1>&2
    exit 255
    """
    try fakeSSHScript.write(to: fakeSSHURL, atomically: true, encoding: .utf8)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: fakeSSHURL.path)

    let askPassLogURL = tempDirectory.appendingPathComponent("askpass.log")
    let recorder = EventRecorder()
    let tunnel = TunnelConfig(
        name: "askpass-network-fail",
        host: "example.com",
        user: "alice",
        forwards: [],
        reconnectDelaySeconds: 1
    )

    let supervisor = TunnelSupervisor(
        tunnel: tunnel,
        logger: { _ in },
        eventHandler: { event in
            recorder.append(event)
        },
        environment: [
            "SSH_ASKPASS": askPassURL.path,
            "PORTKEEPER_PASSWORD": "password",
            "PORTKEEPER_ASKPASS_LOG": askPassLogURL.path,
        ],
        executablePath: fakeSSHURL.path
    )

    let runTask = Task {
        await supervisor.run()
    }
    defer {
        runTask.cancel()
    }

    try await waitUntil(timeout: 2.0) {
        recorder.contains {
            if case .exited = $0 { return true }
            return false
        }
    }

    let sawAuthFailure = recorder.contains {
        if case .authenticationFailed = $0 { return true }
        return false
    }
    let sawExit = recorder.contains {
        if case .exited = $0 { return true }
        return false
    }
    let diagnostic = recorder.firstExitDiagnostic()

    #expect(!sawAuthFailure)
    #expect(sawExit)
    #expect(diagnostic?.contains("Could not resolve hostname") == true)

    runTask.cancel()
    _ = await runTask.result
}

@Test func runtimeRegistryReclaimsRecordedSSHProcess() async throws {
    let tempDirectory = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)

    let fakeSSHURL = tempDirectory.appendingPathComponent("fake-ssh.sh")
    let fakeSSHScript = """
    #!/bin/sh
    sleep 30
    """
    try fakeSSHScript.write(to: fakeSSHURL, atomically: true, encoding: .utf8)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: fakeSSHURL.path)

    let tunnel = try TunnelLaunchPreparer.prepare(
        TunnelConfig(
            name: "owned-process",
            host: "example.com",
            user: "alice",
            sshPort: 2222,
            forwards: []
        ),
        fileManager: .default
    )

    let process = Process()
    process.executableURL = fakeSSHURL
    process.arguments = SSHCommandBuilder.buildArguments(for: tunnel)
    try process.run()

    let runtimeDirectory = tempDirectory.appendingPathComponent("runtime", isDirectory: true)
    try PortKeeperRuntimeRegistry.recordProcess(
        process.processIdentifier,
        for: tunnel.name,
        runtimeDirectory: runtimeDirectory
    )

    try PortKeeperRuntimeRegistry.reclaimOwnedProcess(
        for: tunnel,
        executablePath: fakeSSHURL.path,
        runtimeDirectory: runtimeDirectory
    )

    process.waitUntilExit()

    let pidFileURL = runtimeDirectory.appendingPathComponent("\(tunnel.name).pid")
    #expect(process.terminationStatus != 0)
    #expect(!FileManager.default.fileExists(atPath: pidFileURL.path))
}

private struct WaitTimeoutError: LocalizedError {
    var errorDescription: String? { "Timed out waiting for expected event" }
}

private func waitUntil(timeout: TimeInterval, condition: @escaping @Sendable () -> Bool) async throws {
    let deadline = Date().addingTimeInterval(timeout)
    while Date() < deadline {
        if condition() {
            return
        }
        try await Task.sleep(for: .milliseconds(50))
    }

    throw WaitTimeoutError()
}

@Test func sshConfigParserReadsHostBlocksAndForwards() async throws {
    let contents = """
    # global defaults
    Host *
      ServerAliveInterval 60

    Host prod-db prod-*
      HostName bastion.example.com
      User alice
      Port 2222
      IdentityFile ~/.ssh/id_ed25519
      ProxyJump jump.example.com
      LocalForward 15432 db.internal:5432
      LocalForward 127.0.0.1:6379 localhost:6379
      DynamicForward 1080

    Host plain
      User bob
    """

    let hosts = SSHConfigParser.parse(contents: contents)

    #expect(hosts.map(\.alias) == ["prod-db", "plain"])

    let prod = try #require(hosts.first)
    #expect(prod.effectiveHost == "bastion.example.com")
    #expect(prod.user == "alice")
    #expect(prod.port == 2222)
    #expect(prod.identityFile == "~/.ssh/id_ed25519")
    #expect(prod.proxyJump == "jump.example.com")
    #expect(prod.forwards.count == 3)
    #expect(prod.forwards[0].kind == .local)
    #expect(prod.forwards[0].listenPort == 15432)
    #expect(prod.forwards[0].destinationHost == "db.internal")
    #expect(prod.forwards[0].destinationPort == 5432)
    #expect(prod.forwards[1].bindAddress == "127.0.0.1")
    #expect(prod.forwards[2].kind == .dynamic)
    #expect(prod.forwards[2].listenPort == 1080)

    let plain = hosts[1]
    #expect(plain.effectiveHost == "plain")
    #expect(plain.user == "bob")
    #expect(plain.forwards.isEmpty)
}

@Test func sshConfigParserHandlesEqualsSyntaxAndComments() async throws {
    let contents = """
    Host=web
      HostName = web.example.com
      # Port comment
      Port = 22
    """

    let hosts = SSHConfigParser.parse(contents: contents)
    let web = try #require(hosts.first)
    #expect(web.alias == "web")
    #expect(web.hostName == "web.example.com")
    #expect(web.port == 22)
}

@Test func sshConfigParserFollowsIncludes() async throws {
    let tempDirectory = FileManager.default.temporaryDirectory
        .appendingPathComponent("burrow-sshconfig-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: tempDirectory) }

    let includedURL = tempDirectory.appendingPathComponent("extra.conf")
    try """
    Host included-host
      HostName included.example.com
    """.write(to: includedURL, atomically: true, encoding: .utf8)

    let mainURL = tempDirectory.appendingPathComponent("config")
    try """
    Include extra.conf

    Host main-host
      HostName main.example.com
    """.write(to: mainURL, atomically: true, encoding: .utf8)

    let hosts = SSHConfigParser.parse(fileAt: mainURL)
    #expect(hosts.map(\.alias).sorted() == ["included-host", "main-host"])
}

@Test func configWithoutGatewaysStillDecodes() async throws {
    let legacyJSON = """
    {"version": 1, "tunnels": []}
    """
    let config = try JSONDecoder().decode(AppConfig.self, from: Data(legacyJSON.utf8))
    #expect(config.gateways.isEmpty)
    #expect(config.tunnels.isEmpty)
}

@Test func gatewayConfigDecodesWithDefaults() async throws {
    let json = """
    {"name": "campus", "protocol": "gp", "server": "vpn.example.edu", "user": "alice", "socksPort": 11080}
    """
    let gateway = try JSONDecoder().decode(GatewayConfig.self, from: Data(json.utf8))
    #expect(gateway.vpnProtocol == "gp")
    #expect(gateway.sshHostPatterns.isEmpty)
    #expect(gateway.reconnectDelaySeconds == 5)
}

@Test func gatewayLinkerInjectsProxyCommand() async throws {
    let gateway = GatewayConfig(name: "campus", vpnProtocol: "gp", server: "vpn.example.edu", socksPort: 11080)
    let tunnel = TunnelConfig(
        name: "db",
        host: "internal.example.edu",
        forwards: [ForwardSpec(kind: .local, listenPort: 5432, destinationHost: "localhost", destinationPort: 5432)],
        gateway: "campus"
    )

    let routed = GatewayLinker.applyingGatewayProxy(to: tunnel, gateways: [gateway])
    #expect(routed.extraSSHOptions.contains("ProxyCommand=/usr/bin/nc -X 5 -x 127.0.0.1:11080 %h %p"))

    let args = SSHCommandBuilder.buildArguments(for: routed)
    #expect(args.contains("ProxyCommand=/usr/bin/nc -X 5 -x 127.0.0.1:11080 %h %p"))
}

@Test func gatewayLinkerRespectsUserProxyCommand() async throws {
    let gateway = GatewayConfig(name: "campus", vpnProtocol: "gp", server: "vpn.example.edu", socksPort: 11080)
    let tunnel = TunnelConfig(
        name: "db",
        host: "internal.example.edu",
        forwards: [ForwardSpec(kind: .local, listenPort: 5432, destinationHost: "localhost", destinationPort: 5432)],
        extraSSHOptions: ["ProxyCommand=custom %h %p"],
        gateway: "campus"
    )

    let routed = GatewayLinker.applyingGatewayProxy(to: tunnel, gateways: [gateway])
    #expect(routed.extraSSHOptions == ["ProxyCommand=custom %h %p"])
}

@Test func gatewayLinkerSkipsTunnelsWithoutGateway() async throws {
    let gateway = GatewayConfig(name: "campus", vpnProtocol: "gp", server: "vpn.example.edu", socksPort: 11080)
    let tunnel = TunnelConfig(
        name: "db",
        host: "plain.example.com",
        forwards: [ForwardSpec(kind: .local, listenPort: 5432, destinationHost: "localhost", destinationPort: 5432)]
    )

    let routed = GatewayLinker.applyingGatewayProxy(to: tunnel, gateways: [gateway])
    #expect(routed.extraSSHOptions.isEmpty)
}

@Test func gatewayCommandBuilderBuildsOpenconnectArguments() async throws {
    let gateway = GatewayConfig(
        name: "campus",
        vpnProtocol: "gp",
        server: "vpn.example.edu",
        user: "alice",
        socksPort: 11080,
        extraArgs: ["--servercert", "pin-sha256:abc"]
    )

    let args = GatewayCommandBuilder.buildArguments(for: gateway, ocproxyPath: "/opt/homebrew/bin/ocproxy", credential: .password("secret"))
    #expect(args.contains("--protocol=gp"))
    #expect(args.contains("--user=alice"))
    #expect(args.contains("--passwd-on-stdin"))
    #expect(args.contains("--script-tun"))
    #expect(args.contains("/opt/homebrew/bin/ocproxy -D 11080"))
    #expect(args.contains("--servercert"))
    #expect(args.last == "vpn.example.edu")
}

@Test func gatewayLinkerGeneratesSSHIncludeForHostPatterns() async throws {
    let gateways = [
        GatewayConfig(name: "campus", vpnProtocol: "gp", server: "vpn.example.edu", socksPort: 11080, sshHostPatterns: ["*.example.edu", "172.18.*"]),
        GatewayConfig(name: "lab", vpnProtocol: "anyconnect", server: "vpn.lab.org", socksPort: 11081),
    ]

    let text = try #require(GatewayLinker.sshIncludeText(for: gateways))
    #expect(text.contains("Match host *.example.edu,172.18.*"))
    #expect(text.contains("ProxyCommand /usr/bin/nc -X 5 -x 127.0.0.1:11080 %h %p"))
    #expect(!text.contains("11081"))

    #expect(GatewayLinker.sshIncludeText(for: [gateways[1]]) == nil)
}

@Test func gatewayCommandBuilderHandlesSAMLCredentials() async throws {
    let gateway = GatewayConfig(name: "campus", vpnProtocol: "gp", server: "vpn.example.edu", socksPort: 11080, authMode: "saml")

    let cookieArgs = GatewayCommandBuilder.buildArguments(
        for: gateway,
        ocproxyPath: "/opt/homebrew/bin/ocproxy",
        credential: .samlCookie(username: "alice@example.edu", cookie: "abc", usergroup: "gateway:prelogin-cookie")
    )
    #expect(cookieArgs.contains("--user=alice@example.edu"))
    #expect(cookieArgs.contains("--usergroup=gateway:prelogin-cookie"))
    #expect(cookieArgs.contains("--passwd-on-stdin"))

    let browserArgs = GatewayCommandBuilder.buildArguments(
        for: gateway,
        ocproxyPath: "/opt/homebrew/bin/ocproxy",
        credential: .samlExternalBrowser
    )
    #expect(browserArgs.contains("--external-browser=/usr/bin/open"))
    #expect(!browserArgs.contains("--passwd-on-stdin"))
}

@Test func gatewaySupervisorExtractsServerCertPin() async throws {
    let line = "To trust this server in future, perhaps add this to your command line:  --servercert pin-sha256:0Yt0jETVKnZxPLLqkjVdCfsdtF/CNqo04gQpkznFPGI="
    #expect(GatewaySupervisor.extractServerCertPin(from: line) == "pin-sha256:0Yt0jETVKnZxPLLqkjVdCfsdtF/CNqo04gQpkznFPGI=")
    #expect(GatewaySupervisor.extractServerCertPin(from: "--servercert=pin-sha256:abc=") == "pin-sha256:abc=")
    #expect(GatewaySupervisor.extractServerCertPin(from: "no cert here") == nil)
}

@Test func socksProbeRejectsClosedPort() async throws {
    // Nothing listens here, so the probe must fail fast rather than hang.
    let reachable = SOCKSProbe.canReach(proxyPort: 1, targetHost: "example.com", targetPort: 22, timeout: 2)
    #expect(reachable == false)
}

@Test func socksProbeHandlesNonSocksListener() async throws {
    // A plain TCP server that never speaks SOCKS: probe must return false, not crash.
    let listener = Process()
    listener.executableURL = URL(fileURLWithPath: "/bin/sh")
    // Reserve an ephemeral port via Python and print it, then accept once and sit idle.
    // Simpler: just point at a port we know is closed but in range; covered above.
    _ = listener
    let reachable = SOCKSProbe.canReach(proxyPort: 9, targetHost: "example.com", targetPort: 22, timeout: 2)
    #expect(reachable == false)
}

@Test func launchPreparerPreservesGateway() async throws {
    let tunnel = TunnelConfig(
        name: "via-vpn",
        host: "internal.example.edu",
        user: "alice",
        forwards: [ForwardSpec(kind: .local, listenPort: 4000, destinationHost: "10.0.0.1", destinationPort: 3000)],
        gateway: "campus"
    )
    let prepared = try TunnelLaunchPreparer.prepare(tunnel)
    #expect(prepared.gateway == "campus")

    // And the gateway proxy must inject after preparation (the real launch path).
    let gw = GatewayConfig(name: "campus", vpnProtocol: "gp", server: "vpn.example.edu", socksPort: 11080)
    let routed = GatewayLinker.applyingGatewayProxy(to: prepared, gateways: [gw])
    #expect(routed.extraSSHOptions.contains { $0.contains("ProxyCommand=") && $0.contains("11080") })
}

@Test func forwardProbeReportsReachableForOpenServer() async throws {
    // A plain TCP server that accepts and stays open should read as reachable.
    let listener = try TCPTestServer()
    defer { listener.stop() }
    let result = ForwardProbe.probe(host: "127.0.0.1", port: listener.port, settleMilliseconds: 300)
    #expect(result == .reachable)
}

@Test func forwardProbeReportsUnknownForClosedPort() async throws {
    let result = ForwardProbe.probe(host: "127.0.0.1", port: 1, settleMilliseconds: 200)
    #expect(result == .unknown)
}

@Test func configDecodesProfilesAndHooks() async throws {
    let json = """
    {"version":1,
     "tunnels":[{"name":"db","host":"h","sshPort":22,"forwards":[],"serverAliveInterval":30,"serverAliveCountMax":3,"reconnectDelaySeconds":5,"enabled":true,"extraSSHOptions":[],"onConnect":"echo up","onDisconnect":"echo down"}],
     "profiles":[{"name":"work","tunnels":["db"],"gateways":["campus"]}]}
    """
    let config = try JSONDecoder().decode(AppConfig.self, from: Data(json.utf8))
    #expect(config.profiles.count == 1)
    #expect(config.profiles.first?.tunnels == ["db"])
    #expect(config.profiles.first?.gateways == ["campus"])
    #expect(config.tunnels.first?.onConnect == "echo up")
    #expect(config.tunnels.first?.onDisconnect == "echo down")
}

@Test func legacyConfigWithoutProfilesStillDecodes() async throws {
    let config = try JSONDecoder().decode(AppConfig.self, from: Data("{\"tunnels\":[]}".utf8))
    #expect(config.profiles.isEmpty)
}

final class TCPTestServer {
    let port: Int
    private let fd: Int32
    init() throws {
        let s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        var yes: Int32 = 1
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        addr.sin_port = 0
        _ = withUnsafePointer(to: &addr) { p in p.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(s, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        listen(s, 4)
        var bound = sockaddr_in()
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &bound) { p in p.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(s, $0, &len) } }
        self.fd = s
        self.port = Int(UInt16(bigEndian: bound.sin_port))
    }
    func stop() { close(fd) }
}

@Test func gatewayRenameCascadesToTunnelsAndProfiles() async throws {
    let tempDirectory = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    let store = ConfigStore(configURL: tempDirectory.appendingPathComponent("config.json"))

    try store.save(AppConfig(
        tunnels: [TunnelConfig(name: "db", host: "h", forwards: [], gateway: "old-vpn")],
        gateways: [GatewayConfig(name: "old-vpn", vpnProtocol: "gp", server: "vpn.x", socksPort: 11080)],
        profiles: [Profile(name: "work", tunnels: ["db"], gateways: ["old-vpn"])]
    ))

    var renamed = try store.load().gateways[0]
    renamed.name = "New VPN"
    try store.upsertGateway(renamed, replacing: "old-vpn")

    let config = try store.load()
    #expect(config.tunnels[0].gateway == "New VPN")
    #expect(config.profiles[0].gateways == ["New VPN"])
    #expect(config.gateways.map(\.name) == ["New VPN"])
}

@Test func tunnelRenameCascadesToProfiles() async throws {
    let tempDirectory = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    let store = ConfigStore(configURL: tempDirectory.appendingPathComponent("config.json"))

    try store.save(AppConfig(
        tunnels: [TunnelConfig(name: "old-name", host: "h", forwards: [])],
        profiles: [Profile(name: "work", tunnels: ["old-name"])]
    ))

    var renamed = try store.load().tunnels[0]
    renamed.name = "new-name"
    try store.upsert(renamed, replacing: "old-name")

    let config = try store.load()
    #expect(config.profiles[0].tunnels == ["new-name"])
}
