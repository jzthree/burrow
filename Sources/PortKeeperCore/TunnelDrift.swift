import Foundation

/// The parts of an `ssh` invocation Burrow compares when asking "is the
/// process actually running still the tunnel the config describes?".
///
/// Deliberately narrow: forwards, endpoint and port — the fields `burrow edit`
/// changes. Everything else (known-hosts paths, a gateway's ProxyCommand,
/// credential options) is added at launch time and would report false drift.
public struct SSHInvocationSummary: Equatable, Sendable {
    /// Forward flags normalized to `-R 31703:localhost:2222` form, sorted so
    /// reordering a config's forwards isn't mistaken for drift.
    public var forwards: [String]
    /// The `user@host` ssh was pointed at.
    public var target: String?
    /// The `-p` value, as written.
    public var sshPort: String?

    public init(forwards: [String] = [], target: String? = nil, sshPort: String? = nil) {
        self.forwards = forwards
        self.target = target
        self.sshPort = sshPort
    }
}

/// Compares a tunnel's config with the ssh process that is actually running
/// it. A supervisor holds the definition it launched with, so an edit that
/// hasn't been applied yet leaves the file and the live process disagreeing —
/// invisibly, until something that should work doesn't. `burrow list` surfaces
/// that gap, and `burrow reload` closes it.
public enum TunnelDrift {
    public static func summarize(_ tunnel: TunnelConfig) -> SSHInvocationSummary {
        summarize(arguments: SSHCommandBuilder.buildArguments(for: tunnel))
    }

    /// `ps` reports one flat string. The flags compared here never contain
    /// spaces, and the one argument that does — a gateway's ProxyCommand, a
    /// single `-o` value — is never read, so whitespace splitting is enough.
    public static func summarize(command: String) -> SSHInvocationSummary {
        summarize(arguments: command.split(whereSeparator: \.isWhitespace).map(String.init))
    }

    public static func summarize(arguments: [String]) -> SSHInvocationSummary {
        var forwards: [String] = []
        var sshPort: String?
        var index = 0

        while index < arguments.count {
            let token = arguments[index]
            let next = index + 1 < arguments.count ? arguments[index + 1] : nil

            if token == "-L" || token == "-R" || token == "-D" {
                if let value = next, isForwardSpec(value) {
                    forwards.append("\(token) \(value)")
                    index += 2
                    continue
                }
            } else if token.count > 2, ["-L", "-R", "-D"].contains(String(token.prefix(2))) {
                // ssh also accepts the attached form, `-L3000:localhost:3001`.
                let value = String(token.dropFirst(2))
                if isForwardSpec(value) {
                    forwards.append("\(token.prefix(2)) \(value)")
                    index += 1
                    continue
                }
            } else if token == "-p", sshPort == nil, let value = next, Int(value) != nil {
                // The tunnel's own -p is emitted before extraSSHOptions, so the
                // first one wins over any -p inside a jump ProxyCommand.
                sshPort = value
                index += 2
                continue
            }

            index += 1
        }

        // The remote target is the last argument ssh is given, and never
        // contains whitespace — so it survives the flattening intact.
        let target = arguments.last.flatMap { $0.hasPrefix("-") ? nil : $0 }
        return SSHInvocationSummary(forwards: forwards.sorted(), target: target, sshPort: sshPort)
    }

    public static func differences(configured: TunnelConfig, liveCommand: String) -> [String] {
        differences(configured: summarize(configured), live: summarize(command: liveCommand))
    }

    /// Human-readable differences, config-first. Empty means the live process
    /// is doing exactly what the config says.
    public static func differences(configured: SSHInvocationSummary, live: SSHInvocationSummary) -> [String] {
        var notes: [String] = []
        for forward in configured.forwards where !live.forwards.contains(forward) {
            notes.append("config has \(forward), the live ssh doesn't")
        }
        for forward in live.forwards where !configured.forwards.contains(forward) {
            notes.append("the live ssh has \(forward), config doesn't")
        }
        if let target = configured.target, let liveTarget = live.target, target != liveTarget {
            notes.append("config targets \(target), the live ssh is on \(liveTarget)")
        }
        if let port = configured.sshPort, let livePort = live.sshPort, port != livePort {
            notes.append("config uses ssh port \(port), the live ssh uses \(livePort)")
        }
        return notes
    }

    private static func isForwardSpec(_ value: String) -> Bool {
        guard !value.hasPrefix("-") else { return false }
        let parts = value.split(separator: ":", omittingEmptySubsequences: false)
        switch parts.count {
        case 1: return Int(parts[0]) != nil                          // -D 1080
        case 2: return Int(parts[1]) != nil                          // -D bind:1080
        case 3: return Int(parts[0]) != nil && Int(parts[2]) != nil  // 3000:localhost:3001
        case 4: return Int(parts[1]) != nil && Int(parts[3]) != nil  // bind:3000:localhost:3001
        default: return false
        }
    }
}
