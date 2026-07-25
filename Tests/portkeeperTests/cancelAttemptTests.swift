import Foundation
import Testing
@testable import PortKeeperCore

private final class CancelAttemptRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var startingCount = 0

    func append(_ event: TunnelRuntimeEvent) {
        guard case .starting = event else { return }
        lock.lock()
        startingCount += 1
        lock.unlock()
    }

    var starts: Int {
        lock.lock()
        let value = startingCount
        lock.unlock()
        return value
    }
}

@Test func cancellingCurrentAttemptKeepsSupervisorRetrying() async throws {
    let tempDirectory = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)

    let fakeSSHURL = tempDirectory.appendingPathComponent("fake-ssh.sh")
    try "#!/bin/sh\nexec /bin/sleep 30\n".write(to: fakeSSHURL, atomically: true, encoding: .utf8)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: fakeSSHURL.path)

    let recorder = CancelAttemptRecorder()
    let tunnel = TunnelConfig(
        name: "cancel-attempt-\(UUID().uuidString)",
        host: "example.com",
        forwards: [],
        reconnectDelaySeconds: 1
    )
    let supervisor = TunnelSupervisor(
        tunnel: tunnel,
        logger: { _ in },
        eventHandler: { recorder.append($0) },
        executablePath: fakeSSHURL.path
    )
    let runTask = Task { await supervisor.run() }
    defer { runTask.cancel() }

    try await waitForCancelAttemptCondition(timeout: 2) { recorder.starts >= 1 }
    try await Task.sleep(for: .milliseconds(150))
    #expect(TunnelSupervisor.cancelCurrentAttempt(named: tunnel.name))
    try await waitForCancelAttemptCondition(timeout: 5) { recorder.starts >= 2 }

    runTask.cancel()
    _ = await runTask.result
}

private func waitForCancelAttemptCondition(
    timeout: TimeInterval,
    condition: @escaping @Sendable () -> Bool
) async throws {
    let deadline = Date().addingTimeInterval(timeout)
    while Date() < deadline {
        if condition() { return }
        try await Task.sleep(for: .milliseconds(50))
    }
    throw CancelAttemptTimeout()
}

private struct CancelAttemptTimeout: LocalizedError {
    var errorDescription: String? { "Timed out waiting for supervisor retry" }
}
