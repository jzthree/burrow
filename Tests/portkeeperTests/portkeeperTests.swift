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

    let sawAuthFailure = recorder.events.contains {
        if case .authenticationFailed = $0 { return true }
        return false
    }
    let sawExit = recorder.events.contains {
        if case .exited = $0 { return true }
        return false
    }

    #expect(sawAuthFailure)
    #expect(!sawExit)
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
