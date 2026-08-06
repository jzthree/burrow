import Foundation
import Testing
@testable import PortKeeperCore

/// A real `ps` line for a gateway-routed, jump-hosted tunnel: the ProxyCommand
/// is one `-o` value containing spaces, quotes, and its own `-p`, which is
/// exactly what naive parsing gets wrong.
private let liveNebulaCommand = """
/usr/bin/ssh -N -o ExitOnForwardFailure=yes -o ControlMaster=no -o ControlPath=none \
-o ServerAliveInterval=30 -o ServerAliveCountMax=3 -p 22 \
-o UserKnownHostsFile=/Users/jz/.ssh/burrow/nebula-agent.known_hosts -o StrictHostKeyChecking=accept-new \
-o ProxyCommand=ssh -W '[%h]:%p' -p 3333 -o 'ProxyCommand=/usr/bin/nc -X 5 -x 127.0.0.1:11082 randi.cri.uchicago.edu 22' randi \
-L 3000:localhost:3001 -R 31703:localhost:2222 cri22in002
"""

private func nebulaTunnel(forwards: [ForwardSpec]) -> TunnelConfig {
    TunnelConfig(
        name: "nebula-agent",
        host: "cri22in002",
        sshPort: 22,
        jumpHost: "randi",
        forwards: forwards,
        gateway: "UChicago VPN"
    )
}

private let nebulaForwards = [
    ForwardSpec(kind: .local, listenPort: 3000, destinationHost: "localhost", destinationPort: 3001),
    ForwardSpec(kind: .remote, listenPort: 31703, destinationHost: "localhost", destinationPort: 2222),
]

@Suite struct TunnelDriftTests {
    @Test func liveCommandParsesThroughAQuotedProxyCommand() {
        let summary = TunnelDrift.summarize(command: liveNebulaCommand)
        #expect(summary.forwards == ["-L 3000:localhost:3001", "-R 31703:localhost:2222"])
        #expect(summary.target == "cri22in002")
        // The tunnel's own -p wins over the jump's -p inside the ProxyCommand.
        #expect(summary.sshPort == "22")
    }

    @Test func matchingConfigReportsNoDrift() {
        let notes = TunnelDrift.differences(
            configured: nebulaTunnel(forwards: nebulaForwards),
            liveCommand: liveNebulaCommand
        )
        #expect(notes.isEmpty)
    }

    @Test func forwardAddedInConfigIsReportedAsMissingFromTheLiveProcess() {
        // The reported failure: config lists two reverse forwards, the running
        // ssh only ever had one, and `burrow list` said nothing.
        let configured = nebulaTunnel(forwards: nebulaForwards + [
            ForwardSpec(kind: .remote, listenPort: 46386, destinationHost: "localhost", destinationPort: 22),
        ])
        let notes = TunnelDrift.differences(configured: configured, liveCommand: liveNebulaCommand)
        #expect(notes == ["config has -R 46386:localhost:22, the live ssh doesn't"])
    }

    @Test func forwardRemovedFromConfigIsReportedAsExtraOnTheLiveProcess() {
        let configured = nebulaTunnel(forwards: [nebulaForwards[0]])
        let notes = TunnelDrift.differences(configured: configured, liveCommand: liveNebulaCommand)
        #expect(notes == ["the live ssh has -R 31703:localhost:2222, config doesn't"])
    }

    @Test func endpointAndPortChangesAreReported() {
        var configured = nebulaTunnel(forwards: nebulaForwards)
        configured.user = "jianzhou"
        configured.sshPort = 2222
        let notes = TunnelDrift.differences(configured: configured, liveCommand: liveNebulaCommand)
        #expect(notes.contains("config targets jianzhou@cri22in002, the live ssh is on cri22in002"))
        #expect(notes.contains("config uses ssh port 2222, the live ssh uses 22"))
    }

    @Test func forwardOrderIsNotDrift() {
        let configured = nebulaTunnel(forwards: nebulaForwards.reversed())
        #expect(TunnelDrift.differences(configured: configured, liveCommand: liveNebulaCommand).isEmpty)
    }

    @Test func attachedForwardFormIsUnderstood() {
        let summary = TunnelDrift.summarize(command: "/usr/bin/ssh -N -L3000:localhost:3001 -D1080 host")
        #expect(summary.forwards == ["-D 1080", "-L 3000:localhost:3001"])
    }
}

@Suite struct ReverseForwardRecoveryTests {
    private let conflict = "Warning: remote port forwarding failed for listen port 31703"

    @Test func escalatesFromReclaimToDegradeThenStops() {
        var recovery = ReverseForwardRecovery()
        let tunnel = nebulaTunnel(forwards: nebulaForwards)

        #expect(recovery.next(diagnostic: conflict, tunnel: tunnel) == .reclaim(port: 31703))
        #expect(recovery.next(diagnostic: conflict, tunnel: tunnel) == .degrade(port: 31703))
        // Already degraded: the ordinary backoff takes over from here.
        #expect(recovery.next(diagnostic: conflict, tunnel: tunnel) == .none)
        #expect(recovery.droppedPorts == [31703])
    }

    @Test func degradedLaunchKeepsEveryOtherForward() {
        var recovery = ReverseForwardRecovery()
        let tunnel = nebulaTunnel(forwards: nebulaForwards)
        _ = recovery.next(diagnostic: conflict, tunnel: tunnel)
        _ = recovery.next(diagnostic: conflict, tunnel: tunnel)

        let launched = recovery.applying(to: tunnel)
        #expect(launched.forwards.count == 1)
        #expect(launched.forwards.first?.kind == .local)
        #expect(launched.forwards.first?.listenPort == 3000)
    }

    @Test func neverDegradesAwayTheOnlyForward() {
        // A tunnel whose sole purpose is that reverse forward has nothing to
        // degrade to — an ssh with no forwards would be a lie, not a fallback.
        var recovery = ReverseForwardRecovery()
        let tunnel = nebulaTunnel(forwards: [nebulaForwards[1]])
        #expect(recovery.next(diagnostic: conflict, tunnel: tunnel) == .reclaim(port: 31703))
        #expect(recovery.next(diagnostic: conflict, tunnel: tunnel) == .none)
        #expect(recovery.droppedPorts.isEmpty)
        #expect(recovery.applying(to: tunnel).forwards.count == 1)
    }

    @Test func unrelatedFailuresAreNotRecoveryMaterial() {
        var recovery = ReverseForwardRecovery()
        let tunnel = nebulaTunnel(forwards: nebulaForwards)
        #expect(recovery.next(diagnostic: nil, tunnel: tunnel) == .none)
        #expect(recovery.next(diagnostic: "connection timed out", tunnel: tunnel) == .none)
        // A conflict on a port this tunnel doesn't even forward isn't ours.
        #expect(recovery.next(
            diagnostic: "remote port forwarding failed for listen port 46386",
            tunnel: tunnel
        ) == .none)
    }

    @Test func connectingResetsTheEscalation() {
        var recovery = ReverseForwardRecovery()
        let tunnel = nebulaTunnel(forwards: nebulaForwards)
        _ = recovery.next(diagnostic: conflict, tunnel: tunnel)
        _ = recovery.next(diagnostic: conflict, tunnel: tunnel)
        #expect(recovery.isDegraded)

        recovery.reset()
        #expect(!recovery.isDegraded)
        #expect(recovery.applying(to: tunnel).forwards.count == 2)
        // ...and the next conflict starts over with a fresh reclaim attempt.
        #expect(recovery.next(diagnostic: conflict, tunnel: tunnel) == .reclaim(port: 31703))
    }
}

@Suite struct RemotePortFreeOutputTests {
    @Test func freeCommandLooksForHoldersThreeWaysAndReportsThem() {
        let command = RemoteForwardSupport.freePortCommand(31703)
        #expect(command.contains("lsof -ti tcp:31703"))
        #expect(command.contains("ss -Hltnp"))
        #expect(command.contains("fuser -n tcp 31703"))
        #expect(command.contains("BURROW_PORT_HOLDER"))
        #expect(command.contains("kill -9"))
        #expect(command.contains("BURROW_PORT_FREE"))
        #expect(command.contains("BURROW_PORT_BUSY"))
    }

    @Test func dryRunReportsWithoutSignalling() {
        let command = RemoteForwardSupport.freePortCommand(31703, dryRun: true)
        #expect(command.contains("BURROW_PORT_HOLDER"))
        #expect(!command.contains("kill"))
    }

    @Test func parsesHoldersAndStatus() {
        let outcome = RemoteForwardSupport.parseFreePortOutput(
            standardOutput: """
            BURROW_PORT_HOLDER 41234 sshd: alice@notty
            BURROW_PORT_FREE
            """,
            standardError: ""
        )
        #expect(outcome.status == .freed)
        #expect(outcome.holders == ["41234 (sshd: alice@notty)"])
        #expect(outcome.holderSummary == "41234 (sshd: alice@notty)")
    }

    @Test func parsesStillHeldWithAnUnsignalableHolder() {
        let outcome = RemoteForwardSupport.parseFreePortOutput(
            standardOutput: """
            BURROW_PORT_HOLDER 991 sshd: bob@notty
            BURROW_PORT_KILL_FAILED 991
            BURROW_PORT_BUSY
            """,
            standardError: ""
        )
        #expect(outcome.status == .busy)
        #expect(outcome.unkillable == ["991"])
    }

    @Test func hostWithoutSsOrLsofIsUnverifiedNotFailed() {
        let outcome = RemoteForwardSupport.parseFreePortOutput(
            standardOutput: "BURROW_PORT_UNVERIFIED\n",
            standardError: ""
        )
        #expect(outcome.status == .unverified)
    }

    @Test func noMarkerMeansTheHostWasNeverReached() {
        let outcome = RemoteForwardSupport.parseFreePortOutput(
            standardOutput: "",
            standardError: "ssh: connect to host cri22in002 port 22: Operation timed out\n"
        )
        #expect(outcome.status == .unreachable)
        #expect(outcome.detail?.contains("Operation timed out") == true)
    }

    @Test func degradedStatusNamesThePortToFree() {
        #expect(RemoteForwardSupport.degradedForwardPort(
            in: "Connected without -R 31703 — the remote won't release that port"
        ) == 31703)
        #expect(RemoteForwardSupport.degradedForwardPort(in: "Connected") == nil)
    }
}

@Suite struct DegradedReverseForwardTests {
    /// The whole escalation against a stand-in ssh: the first two launches
    /// fail the way ssh does when the remote won't rebind a reverse forward
    /// (warning on stderr, clean exit courtesy of ExitOnForwardFailure), the
    /// reclaim command reports the port still held, and the third launch —
    /// the degraded one — stays up. Before this, that tunnel simply never
    /// connected again: one stale listener took every forward down with it.
    @Test func stillHeldPortDegradesInsteadOfKillingTheTunnel() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let counter = directory.appendingPathComponent("attempts")
        let scriptURL = directory.appendingPathComponent("fake-ssh.sh")
        // Maintenance calls (the reclaim) arrive with arguments; tunnel
        // launches don't, which is how the stand-in tells them apart.
        let script = """
        #!/bin/sh
        if [ $# -gt 0 ]; then
          echo "BURROW_PORT_HOLDER 999 sshd: tester@notty"
          echo BURROW_PORT_BUSY
          exit 0
        fi
        echo x >> "\(counter.path)"
        attempts=$(wc -l < "\(counter.path)")
        if [ "$attempts" -ge 3 ]; then
          sleep 30
          exit 0
        fi
        echo "Warning: remote port forwarding failed for listen port 31703" 1>&2
        exit 0
        """
        try script.write(to: scriptURL, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: scriptURL.path)

        let recorder = EventRecorder()
        let transcript = LineRecorder()
        let tunnel = TunnelConfig(
            name: "nebula-agent",
            host: "cri22in002",
            forwards: [
                ForwardSpec(kind: .remote, listenPort: 31703, destinationHost: "localhost", destinationPort: 2222),
                ForwardSpec(kind: .remote, listenPort: 31704, destinationHost: "localhost", destinationPort: 22),
            ],
            reconnectDelaySeconds: 1
        )
        let supervisor = TunnelSupervisor(
            tunnel: tunnel,
            logger: { transcript.append($0) },
            eventHandler: { recorder.append($0) },
            executablePath: scriptURL.path
        )

        let runTask = Task { await supervisor.run() }
        defer { runTask.cancel() }

        let degraded = await pollForEvent(timeout: 20) {
            recorder.contains {
                if case .degraded = $0 { return true }
                return false
            }
        }
        #expect(degraded)
        // It is genuinely up, not merely "not failing".
        #expect(recorder.contains {
            if case .connected = $0 { return true }
            return false
        })

        let log = transcript.text()
        // It tried to free the port first, and said who was holding it.
        #expect(log.contains("trying to free it"))
        #expect(log.contains("sshd: tester@notty"))
        // ...and says how to get the forward back.
        #expect(log.contains("burrow reclaim nebula-agent --port 31703"))
    }
}

private final class LineRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var lines: [String] = []

    func append(_ line: String) {
        lock.lock()
        lines.append(line)
        lock.unlock()
    }

    func text() -> String {
        lock.lock()
        let joined = lines.joined(separator: "\n")
        lock.unlock()
        return joined
    }
}

private func pollForEvent(timeout: TimeInterval, _ condition: () -> Bool) async -> Bool {
    let deadline = Date().addingTimeInterval(timeout)
    while Date() < deadline {
        if condition() { return true }
        try? await Task.sleep(for: .milliseconds(100))
    }
    return condition()
}

@Suite struct SilentSignInRetryTests {
    @Test func widensQuicklyThenHoldsAtTheCap() {
        #expect(SilentSignInRetry.delaySeconds(attempt: 1) == 20)
        #expect(SilentSignInRetry.delaySeconds(attempt: 2) == 60)
        #expect(SilentSignInRetry.delaySeconds(attempt: 3) == 180)
        #expect(SilentSignInRetry.delaySeconds(attempt: 4) == 600)
        #expect(SilentSignInRetry.delaySeconds(attempt: 5) == 1800)
        // Never gives up: the fix for a failed attempt is usually the network
        // coming back, which has no deadline.
        #expect(SilentSignInRetry.delaySeconds(attempt: 50) == 1800)
    }

    @Test func firstHourOfOutageCostsAHandfulOfAttempts() {
        // Cheap enough to run unattended forever: an hour of downtime is ~7
        // attempts, not one every 20 seconds.
        var elapsed = 0, attempts = 0
        while elapsed < 3600 {
            attempts += 1
            elapsed += SilentSignInRetry.delaySeconds(attempt: attempts)
        }
        #expect(attempts <= 8)
        #expect(attempts >= 4)
    }

    @Test func degradesGracefullyOnNonsenseInput() {
        #expect(SilentSignInRetry.delaySeconds(attempt: 0) == 20)
        #expect(SilentSignInRetry.delaySeconds(attempt: -3) == 20)
    }

    @Test func describesDelaysForTheStatusRow() {
        #expect(SilentSignInRetry.describeDelay(20) == "20s")
        #expect(SilentSignInRetry.describeDelay(180) == "3m")
        #expect(SilentSignInRetry.describeDelay(1800) == "30m")
    }
}

@Suite struct BoundedLogFileTests {
    @Test func collapsesRepeatsAndRotatesAtTheCap() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let url = directory.appendingPathComponent("tunnel.log")
        let log = BoundedLogFile(url: url, maxBytes: 2_000, window: 300, label: "test.bounded-log")

        for index in 0..<400 {
            log.append(source: "nebula-agent", "ssh exited with code 15. Reconnecting in \(index % 60)s.")
        }
        // Drain the log's serial queue.
        let drained = expectation(within: 5) {
            (try? String(contentsOf: url, encoding: .utf8))?.isEmpty == false
        }
        #expect(drained)

        let contents = try String(contentsOf: url, encoding: .utf8)
        // Digits are normalized, so 400 near-identical lines collapse to one.
        #expect(contents.split(whereSeparator: \.isNewline).count == 1)
        #expect(contents.contains("[nebula-agent]"))
        // Nothing rotated: dedup kept it far under the cap.
        #expect(!FileManager.default.fileExists(atPath: directory.appendingPathComponent("tunnel.1.log").path))
    }

    @Test func rotationCapsTotalSizeWhenEveryLineIsDistinct() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let url = directory.appendingPathComponent("tunnel.log")
        let log = BoundedLogFile(url: url, maxBytes: 1_000, window: 300, label: "test.bounded-log-rotate")

        for index in 0..<200 {
            log.append(source: "t", "distinct message \(UUID().uuidString) number \(index)")
        }
        let rolled = directory.appendingPathComponent("tunnel.1.log")
        let rotated = expectation(within: 5) {
            FileManager.default.fileExists(atPath: rolled.path)
        }
        #expect(rotated)

        // Two files, each bounded: growth is capped no matter what dedup misses.
        let sizeOf: (URL) -> Int = { url in
            ((try? FileManager.default.attributesOfItem(atPath: url.path)[.size]) as? Int) ?? 0
        }
        #expect(sizeOf(url) + sizeOf(rolled) < 4_000)
    }
}

/// Polls `condition` until it holds or the deadline passes — the log file is
/// written on its own queue, so assertions have to wait for it.
private func expectation(within seconds: TimeInterval, _ condition: () -> Bool) -> Bool {
    let deadline = Date().addingTimeInterval(seconds)
    while Date() < deadline {
        if condition() { return true }
        usleep(50_000)
    }
    return condition()
}
