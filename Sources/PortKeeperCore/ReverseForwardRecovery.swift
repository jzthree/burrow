import Foundation

/// What to do when ssh refuses to start because the remote won't bind a
/// reverse (`-R`) forward's port — "remote port forwarding failed for listen
/// port 46386". Burrow launches ssh with `ExitOnForwardFailure=yes` (a forward
/// that silently didn't bind is worse than a visible failure), so one stale
/// listener on the remote takes down the *whole* tunnel: every local forward
/// and every working reverse forward with it, for a port nothing may still
/// need. That failure is latent — it fires at the next reconnect, long after
/// whatever caused it, and looks unrelated to anything the user did.
///
/// The escalation is short and per connection cycle: try to free the port
/// once, then connect anyway *without* that one forward rather than refusing
/// the whole tunnel. Reaching connected resets everything, so once the remote
/// lets the port go, the full forward set returns on the next reconnect.
public struct ReverseForwardRecovery: Sendable {
    public enum Step: Equatable, Sendable {
        /// Try to terminate whatever holds `port` on the remote, then retry
        /// the full forward set.
        case reclaim(port: Int)
        /// Give up on `port` and connect with the remaining forwards.
        case degrade(port: Int)
        /// Nothing to recover — the caller's ordinary retry applies.
        case none
    }

    private var reclaimAttempted: Set<Int> = []
    private var degradedPorts: Set<Int> = []

    public init() {}

    /// Reverse-forward ports currently dropped from the launch.
    public var droppedPorts: [Int] { degradedPorts.sorted() }

    public var isDegraded: Bool { !degradedPorts.isEmpty }

    /// The next recovery step given the diagnostic a failed run produced.
    public mutating func next(diagnostic: String?, tunnel: TunnelConfig) -> Step {
        guard let diagnostic,
              diagnostic.lowercased().contains("remote port forwarding failed") else {
            return .none
        }
        // ssh usually names the port it couldn't bind; fall back to the
        // tunnel's own reverse port when the message is terser than expected.
        guard let port = RemoteForwardSupport.conflictingPort(in: diagnostic)
            ?? RemoteForwardSupport.reverseForwardPort(of: tunnel) else {
            return .none
        }
        guard tunnel.forwards.contains(where: { $0.kind == .remote && $0.listenPort == port }) else {
            return .none
        }

        if !reclaimAttempted.contains(port) {
            reclaimAttempted.insert(port)
            return .reclaim(port: port)
        }

        guard !degradedPorts.contains(port) else {
            return .none
        }
        // Dropping the last forward would leave an ssh session that does
        // nothing; keep retrying the real thing instead of pretending.
        var remaining = tunnel.forwards
        remaining.removeAll { $0.kind == .remote && ($0.listenPort == port || degradedPorts.contains($0.listenPort)) }
        guard !remaining.isEmpty else {
            return .none
        }

        degradedPorts.insert(port)
        return .degrade(port: port)
    }

    /// Called when a run reaches connected: the next failure starts the
    /// escalation over, and the dropped forwards are tried again.
    public mutating func reset() {
        reclaimAttempted.removeAll()
        degradedPorts.removeAll()
    }

    /// The tunnel to actually launch — the configured one minus the reverse
    /// forwards the remote refuses to bind.
    public func applying(to tunnel: TunnelConfig) -> TunnelConfig {
        guard !degradedPorts.isEmpty else { return tunnel }
        var reduced = tunnel
        reduced.forwards.removeAll { $0.kind == .remote && degradedPorts.contains($0.listenPort) }
        return reduced
    }
}
