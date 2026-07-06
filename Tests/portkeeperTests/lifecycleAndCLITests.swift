import Foundation
import Testing
@testable import PortKeeperCore

// MARK: - SSHHostWarmer lifecycle

/// A fake ssh that keeps master state in a marker file: `-O check` reports it,
/// `-O exit` removes it, and a plain warm invocation creates it.
private func writeFakeMasterSSH(in directory: URL, marker: URL) throws -> URL {
    let scriptURL = directory.appendingPathComponent("fake-master-ssh.sh")
    let script = """
    #!/bin/sh
    MARKER="\(marker.path)"
    case "$*" in
      *"-O check"*)
        [ -f "$MARKER" ] && exit 0
        exit 1
        ;;
      *"-O exit"*)
        rm -f "$MARKER"
        exit 0
        ;;
      *)
        touch "$MARKER"
        exit 0
        ;;
    esac
    """
    try script.write(to: scriptURL, atomically: true, encoding: .utf8)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: scriptURL.path)
    return scriptURL
}

@Test func warmerEstablishesChecksAndCoolsMaster() async throws {
    let tempDirectory = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
    let marker = tempDirectory.appendingPathComponent("master.marker")
    let ssh = try writeFakeMasterSSH(in: tempDirectory, marker: marker)

    #expect(!SSHHostWarmer.isWarm(alias: "devbox", executablePath: ssh.path))

    let outcome = SSHHostWarmer.warm(alias: "devbox", environment: nil, executablePath: ssh.path)
    #expect(outcome.succeeded)
    #expect(SSHHostWarmer.isWarm(alias: "devbox", executablePath: ssh.path))

    SSHHostWarmer.cool(alias: "devbox", executablePath: ssh.path)
    #expect(!SSHHostWarmer.isWarm(alias: "devbox", executablePath: ssh.path))
}

@Test func warmerFailureCapturesAuthDiagnosis() async throws {
    let tempDirectory = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
    let scriptURL = tempDirectory.appendingPathComponent("fake-ssh.sh")
    let script = """
    #!/bin/sh
    echo "alice@devbox: Permission denied (keyboard-interactive)." 1>&2
    exit 255
    """
    try script.write(to: scriptURL, atomically: true, encoding: .utf8)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: scriptURL.path)

    let outcome = SSHHostWarmer.warm(alias: "devbox", environment: nil, executablePath: scriptURL.path)
    #expect(!outcome.succeeded)
    #expect(WarmDiagnosis.classify(outcome.output) == .authRejected)
}

@Test func warmerPassesAskpassEnvironmentThrough() async throws {
    let tempDirectory = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
    let scriptURL = tempDirectory.appendingPathComponent("fake-ssh.sh")
    // Fails unless the caller's environment overlay reached the child.
    let script = """
    #!/bin/sh
    [ "$BURROW_TEST_TOKEN" = "sesame" ] && exit 0
    echo "missing token" 1>&2
    exit 1
    """
    try script.write(to: scriptURL, atomically: true, encoding: .utf8)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: scriptURL.path)

    let denied = SSHHostWarmer.warm(alias: "devbox", environment: nil, executablePath: scriptURL.path)
    #expect(!denied.succeeded)

    let granted = SSHHostWarmer.warm(
        alias: "devbox",
        environment: ["BURROW_TEST_TOKEN": "sesame"],
        executablePath: scriptURL.path
    )
    #expect(granted.succeeded)
}

// MARK: - GatewaySupervisor lifecycle

final class GatewayEventRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private(set) var events: [GatewayRuntimeEvent] = []

    func append(_ event: GatewayRuntimeEvent) {
        lock.lock()
        events.append(event)
        lock.unlock()
    }

    func count(where predicate: (GatewayRuntimeEvent) -> Bool) -> Int {
        lock.lock()
        let result = events.filter(predicate).count
        lock.unlock()
        return result
    }

    func contains(where predicate: (GatewayRuntimeEvent) -> Bool) -> Bool {
        count(where: predicate) > 0
    }
}

/// These tests point BURROW_OPENCONNECT/BURROW_OCPROXY at fake scripts via the
/// process environment, so they must not run concurrently with each other.
@Suite(.serialized) struct GatewaySupervisorLifecycleTests {
    private func withFakeOpenconnect<T>(script: String, body: () async throws -> T) async throws -> T {
        let tempDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        let openconnectURL = tempDirectory.appendingPathComponent("fake-openconnect.sh")
        try script.write(to: openconnectURL, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: openconnectURL.path)
        // ocproxy is only referenced in the generated arguments, never spawned
        // directly, but the supervisor requires it to exist on the lookup path.
        let ocproxyURL = tempDirectory.appendingPathComponent("fake-ocproxy.sh")
        try "#!/bin/sh\nexit 0\n".write(to: ocproxyURL, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: ocproxyURL.path)

        setenv("BURROW_OPENCONNECT", openconnectURL.path, 1)
        setenv("BURROW_OCPROXY", ocproxyURL.path, 1)
        defer {
            unsetenv("BURROW_OPENCONNECT")
            unsetenv("BURROW_OCPROXY")
        }
        return try await body()
    }

    @Test func authFailureLineStopsRetries() async throws {
        try await withFakeOpenconnect(script: """
        #!/bin/sh
        echo "Login failed."
        exit 1
        """) {
            let gateway = GatewayConfig(name: "test-vpn", vpnProtocol: "anyconnect", server: "vpn.example.edu", socksPort: 39472)
            let recorder = GatewayEventRecorder()
            let supervisor = GatewaySupervisor(
                gateway: gateway,
                credential: .password("wrong"),
                logger: { _ in },
                eventHandler: { recorder.append($0) }
            )

            // Auth failure must break the loop on its own — no cancellation.
            await supervisor.run()

            #expect(recorder.contains { if case .starting = $0 { return true }; return false })
            #expect(recorder.contains { if case .authenticationFailed = $0 { return true }; return false })
            #expect(!recorder.contains { if case .connected = $0 { return true }; return false })
        }
    }

    @Test func cleanExitReconnectsAfterDelay() async throws {
        try await withFakeOpenconnect(script: """
        #!/bin/sh
        echo "session ended"
        exit 0
        """) {
            let gateway = GatewayConfig(
                name: "test-vpn",
                vpnProtocol: "anyconnect",
                server: "vpn.example.edu",
                socksPort: 39473,
                reconnectDelaySeconds: 1
            )
            let recorder = GatewayEventRecorder()
            let supervisor = GatewaySupervisor(
                gateway: gateway,
                credential: .password("pw"),
                logger: { _ in },
                eventHandler: { recorder.append($0) }
            )

            let task = Task { await supervisor.run() }
            // Two exited events prove the supervisor came back after the delay.
            let deadline = Date().addingTimeInterval(15)
            while recorder.count(where: { if case .exited = $0 { return true }; return false }) < 2,
                  Date() < deadline {
                try await Task.sleep(for: .milliseconds(100))
            }
            task.cancel()
            await task.value

            #expect(recorder.count(where: { if case .exited = $0 { return true }; return false }) >= 2)
        }
    }

    @Test func openSOCKSPortReportsConnected() async throws {
        let socksPort = 39474
        try await withFakeOpenconnect(script: """
        #!/bin/sh
        exec /usr/bin/nc -l 127.0.0.1 \(socksPort)
        """) {
            let gateway = GatewayConfig(name: "test-vpn", vpnProtocol: "anyconnect", server: "vpn.example.edu", socksPort: socksPort)
            let recorder = GatewayEventRecorder()
            let supervisor = GatewaySupervisor(
                gateway: gateway,
                credential: .password("pw"),
                logger: { _ in },
                eventHandler: { recorder.append($0) }
            )

            let task = Task { await supervisor.run() }
            let deadline = Date().addingTimeInterval(15)
            while !recorder.contains(where: { if case .connected = $0 { return true }; return false }),
                  Date() < deadline {
                try await Task.sleep(for: .milliseconds(100))
            }
            task.cancel()
            await task.value

            #expect(recorder.contains { if case .connected = $0 { return true }; return false })
        }
    }
}

// MARK: - CLI smoke tests

/// Locates the `burrow` binary built alongside the test bundle. Bundle(for:)
/// finds the .xctest bundle even under the SwiftPM runner, where
/// Bundle.allBundles does not enumerate it.
private func burrowBinaryURL() throws -> URL {
    let testBundle = Bundle(for: GatewayEventRecorder.self)
    let url = testBundle.bundleURL.deletingLastPathComponent().appendingPathComponent("burrow")
    guard FileManager.default.isExecutableFile(atPath: url.path) else {
        throw CLITestError("burrow binary not found next to the test bundle at \(url.path)")
    }
    return url
}

private struct CLITestError: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

private struct CLIResult {
    let exitCode: Int32
    let stdout: String
    let stderr: String
}

private func runBurrow(_ arguments: [String], configURL: URL) throws -> CLIResult {
    let process = Process()
    process.executableURL = try burrowBinaryURL()
    process.arguments = arguments
    var environment = ProcessInfo.processInfo.environment
    environment["BURROW_CONFIG"] = configURL.path
    process.environment = environment
    let outPipe = Pipe()
    let errPipe = Pipe()
    process.standardOutput = outPipe
    process.standardError = errPipe
    try process.run()
    let stdout = outPipe.fileHandleForReading.readDataToEndOfFile()
    let stderr = errPipe.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    return CLIResult(
        exitCode: process.terminationStatus,
        stdout: String(data: stdout, encoding: .utf8) ?? "",
        stderr: String(data: stderr, encoding: .utf8) ?? ""
    )
}

@Test func cliTunnelLifecycleSmokeTest() async throws {
    let tempDirectory = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
    let configURL = tempDirectory.appendingPathComponent("config.json")

    let initResult = try runBurrow(["init"], configURL: configURL)
    #expect(initResult.exitCode == 0)
    #expect(FileManager.default.fileExists(atPath: configURL.path))

    let addResult = try runBurrow([
        "add",
        "--name", "smoke-db",
        "--host", "bastion.example.com",
        "--user", "alice",
        "--local", "127.0.0.1:15432:127.0.0.1:5432",
    ], configURL: configURL)
    #expect(addResult.exitCode == 0)

    let listResult = try runBurrow(["list"], configURL: configURL)
    #expect(listResult.exitCode == 0)
    #expect(listResult.stdout.contains("smoke-db"))
    #expect(listResult.stdout.contains("enabled"))

    let disableResult = try runBurrow(["disable", "smoke-db"], configURL: configURL)
    #expect(disableResult.exitCode == 0)
    let disabledList = try runBurrow(["list"], configURL: configURL)
    #expect(disabledList.stdout.contains("disabled"))

    let printResult = try runBurrow(["print-config"], configURL: configURL)
    #expect(printResult.exitCode == 0)
    #expect(printResult.stdout.contains("\"smoke-db\""))

    let removeResult = try runBurrow(["remove", "smoke-db"], configURL: configURL)
    #expect(removeResult.exitCode == 0)
    let emptyList = try runBurrow(["list"], configURL: configURL)
    #expect(emptyList.stdout.contains("No tunnels configured"))
}

@Test func cliRejectsUnknownCommandsAndMissingTunnels() async throws {
    let tempDirectory = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
    let configURL = tempDirectory.appendingPathComponent("config.json")
    _ = try runBurrow(["init"], configURL: configURL)

    let unknown = try runBurrow(["frobnicate"], configURL: configURL)
    #expect(unknown.exitCode == 1)
    #expect(unknown.stderr.contains("unknown command"))

    let missing = try runBurrow(["enable", "no-such-tunnel"], configURL: configURL)
    #expect(missing.exitCode == 1)
    #expect(missing.stderr.contains("not found"))

    let addWithoutForward = try runBurrow(
        ["add", "--name", "x", "--host", "h.example.com"],
        configURL: configURL
    )
    #expect(addWithoutForward.exitCode == 1)
    #expect(addWithoutForward.stderr.contains("--local"))
}

// MARK: - Batch-2 fixes: parser wildcards, config errors, symlinks, CLI

@Test func parserFoldsWildcardDefaultsIntoConcreteHosts() async throws {
    // The conventional layout: concrete hosts first, `Host *` defaults last.
    let hosts = SSHConfigParser.parse(contents: """
    Host prod
        HostName 10.0.0.1

    Host special
        User alice
        HostName 10.0.0.2

    Host *
        User git
        IdentityFile ~/.ssh/id_ed25519
    """)

    let prod = try #require(hosts.first { $0.alias == "prod" })
    #expect(prod.user == "git")
    #expect(prod.identityFile == "~/.ssh/id_ed25519")
    #expect(prod.hostName == "10.0.0.1")

    // First-obtained wins (like ssh): the stanza's own value came first.
    let special = try #require(hosts.first { $0.alias == "special" })
    #expect(special.user == "alice")

    // Wildcard-only stanzas still don't become entries themselves.
    #expect(!hosts.contains { $0.alias == "*" })

    // And like ssh, a `Host *` ABOVE a stanza takes precedence over it.
    let wildcardFirst = SSHConfigParser.parse(contents: """
    Host *
        User git

    Host special
        User alice
    """)
    #expect(wildcardFirst.first { $0.alias == "special" }?.user == "git")
}

@Test func parserHonorsNegatedPatterns() async throws {
    let hosts = SSHConfigParser.parse(contents: """
    Host * !prod
        User git

    Host prod
        HostName 10.0.0.1

    Host dev
        HostName 10.0.0.2
    """)

    #expect(hosts.first { $0.alias == "prod" }?.user == nil)
    #expect(hosts.first { $0.alias == "dev" }?.user == "git")
}

@Test func configLoadNamesTheBadField() async throws {
    let tempDirectory = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
    let configURL = tempDirectory.appendingPathComponent("config.json")
    // Start from a valid config, then corrupt one field's type.
    let store = ConfigStore(configURL: configURL)
    try store.save(AppConfig(tunnels: [
        TunnelConfig(name: "db", host: "h", forwards: [
            ForwardSpec(kind: .local, listenPort: 15432, destinationHost: "127.0.0.1", destinationPort: 5432),
        ]),
    ]))
    let valid = try String(contentsOf: configURL, encoding: .utf8)
    try valid.replacingOccurrences(of: "15432", with: "\"oops\"")
        .write(to: configURL, atomically: true, encoding: .utf8)

    do {
        _ = try store.load()
        Issue.record("expected load to throw")
    } catch let error as ConfigFileError {
        #expect(error.message.contains("tunnels[0]"))
        #expect(error.message.contains("listenPort"))
        #expect(error.message.contains("wrong type"))
    }
}

@Test func configMutatePersistsAndReturnsValue() async throws {
    let tempDirectory = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    let store = ConfigStore(configURL: tempDirectory.appendingPathComponent("config.json"))
    try store.save(AppConfig(tunnels: [TunnelConfig(name: "a", host: "h", forwards: [])]))

    let removed = try store.mutate { config -> Bool in
        config.tunnels.removeAll { $0.name == "a" }
        return true
    }
    #expect(removed)
    #expect(try store.load().tunnels.isEmpty)
}

@Test func sshConfigWriterPreservesSymlinkedConfig() async throws {
    let tempDirectory = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
    let realConfig = tempDirectory.appendingPathComponent("dotfiles-config")
    try "Host existing\n    HostName 10.0.0.9\n".write(to: realConfig, atomically: true, encoding: .utf8)
    let link = tempDirectory.appendingPathComponent("config")
    try FileManager.default.createSymbolicLink(at: link, withDestinationURL: realConfig)

    try SSHConfigWriter.appendHost(
        SSHConfigWriter.HostEntry(alias: "added", hostName: "10.0.0.10"),
        to: link
    )

    let attributes = try FileManager.default.attributesOfItem(atPath: link.path)
    #expect(attributes[.type] as? FileAttributeType == .typeSymbolicLink)
    let contents = try String(contentsOf: realConfig, encoding: .utf8)
    #expect(contents.contains("Host added"))
    #expect(contents.contains("Host existing"))
}

@Test func cliVersionEditAndJSONOutput() async throws {
    let tempDirectory = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
    let configURL = tempDirectory.appendingPathComponent("config.json")

    let version = try runBurrow(["--version"], configURL: configURL)
    #expect(version.exitCode == 0)
    #expect(version.stdout.contains("burrow "))

    _ = try runBurrow(["init"], configURL: configURL)
    _ = try runBurrow([
        "add", "--name", "edit-me", "--host", "old.example.com",
        "--local", "127.0.0.1:18080:127.0.0.1:80",
    ], configURL: configURL)

    let edit = try runBurrow(
        ["edit", "edit-me", "--host", "new.example.com", "--user", "alice"],
        configURL: configURL
    )
    #expect(edit.exitCode == 0)

    let json = try runBurrow(["list", "--json"], configURL: configURL)
    #expect(json.exitCode == 0)
    struct Row: Decodable {
        let name: String
        let host: String
        let user: String?
    }
    let rows = try JSONDecoder().decode([Row].self, from: Data(json.stdout.utf8))
    #expect(rows.count == 1)
    #expect(rows.first?.host == "new.example.com")
    #expect(rows.first?.user == "alice")

    let missing = try runBurrow(["edit", "nope", "--host", "x"], configURL: configURL)
    #expect(missing.exitCode == 1)
}

// MARK: - Jump-aware gateway routing

@Test func jumpHostSpecParsesCommonForms() async throws {
    let plain = try #require(JumpHostSpec.firstHop(of: "randi"))
    #expect(plain.host == "randi")
    #expect(plain.user == nil)
    #expect(plain.port == nil)
    #expect(!plain.isMultiHop)

    let full = try #require(JumpHostSpec.firstHop(of: "alice@bastion.example.com:2222"))
    #expect(full.user == "alice")
    #expect(full.host == "bastion.example.com")
    #expect(full.port == 2222)

    let ipv6 = try #require(JumpHostSpec.firstHop(of: "[::1]:2200"))
    #expect(ipv6.host == "::1")
    #expect(ipv6.port == 2200)

    let bareIPv6 = try #require(JumpHostSpec.firstHop(of: "fe80::1"))
    #expect(bareIPv6.host == "fe80::1")
    #expect(bareIPv6.port == nil)

    let chain = try #require(JumpHostSpec.firstHop(of: "hop1,hop2"))
    #expect(chain.host == "hop1")
    #expect(chain.isMultiHop)

    #expect(JumpHostSpec.firstHop(of: "") == nil)
}

@Test func gatewayLinkerRoutesJumpTunnelsAtTheFirstHop() async throws {
    let gateway = GatewayConfig(name: "campus", vpnProtocol: "anyconnect", server: "vpn.example.edu", socksPort: 11082)
    let sshHosts = [SSHConfigHost(alias: "randi", hostName: "randi.cri.uchicago.edu", user: "jianzhou")]
    let tunnel = TunnelConfig(
        name: "nebula-agent",
        host: "cri22in001",
        jumpHost: "randi",
        forwards: [ForwardSpec(kind: .local, listenPort: 3000, destinationHost: "localhost", destinationPort: 3000)],
        gateway: "campus"
    )

    let routed = GatewayLinker.applyingGatewayProxy(to: tunnel, gateways: [gateway], sshHosts: sshHosts)

    // -J is gone; the first hop is dialed through the gateway instead, with
    // the alias resolved to a name the proxy's DNS can find.
    #expect(routed.jumpHost == nil)
    let proxy = try #require(routed.extraSSHOptions.first { $0.hasPrefix("ProxyCommand=") })
    #expect(proxy.contains("ssh -W '[%h]:%p'"))
    #expect(proxy.contains("nc -X 5 -x 127.0.0.1:11082 randi.cri.uchicago.edu 22"))
    #expect(proxy.hasSuffix(" randi"))
    // ssh would silently ignore a plain ProxyCommand next to -J; make sure we
    // didn't leave that combination behind.
    #expect(!proxy.contains("%h %p'") || proxy.contains("randi.cri.uchicago.edu"))

    // The supervised command builds without -J and with the nested proxy.
    let args = SSHCommandBuilder.buildArguments(for: routed)
    #expect(!args.contains("-J"))
    #expect(args.contains { $0.hasPrefix("ProxyCommand=ssh -W") })
}

@Test func gatewayLinkerLeavesMultiHopJumpsAlone() async throws {
    let gateway = GatewayConfig(name: "campus", vpnProtocol: "anyconnect", server: "vpn.example.edu", socksPort: 11082)
    let tunnel = TunnelConfig(name: "t", host: "target", jumpHost: "hop1,hop2", forwards: [], gateway: "campus")

    let routed = GatewayLinker.applyingGatewayProxy(to: tunnel, gateways: [gateway], sshHosts: [])

    #expect(routed.jumpHost == "hop1,hop2")
    #expect(!routed.extraSSHOptions.contains { $0.lowercased().hasPrefix("proxycommand") })
}

@Test func gatewayProbeEndpointPrefersTheJumpHop() async throws {
    let sshHosts = [SSHConfigHost(alias: "randi", hostName: "randi.cri.uchicago.edu", port: 22)]

    let jumpTunnel = TunnelConfig(name: "t", host: "cri22in001", jumpHost: "randi", forwards: [])
    let jumpProbe = GatewayLinker.gatewayProbeEndpoint(for: jumpTunnel, sshHosts: sshHosts)
    #expect(jumpProbe.host == "randi.cri.uchicago.edu")
    #expect(jumpProbe.port == 22)

    let directTunnel = TunnelConfig(name: "t", host: "db.example.com", sshPort: 2222, forwards: [])
    let directProbe = GatewayLinker.gatewayProbeEndpoint(for: directTunnel, sshHosts: sshHosts)
    #expect(directProbe.host == "db.example.com")
    #expect(directProbe.port == 2222)
}
