import Foundation

/// Append-only writer for ~/.ssh/config. Burrow adds new `Host` blocks (each
/// tagged so they're identifiable) and never edits or removes what's already
/// there, keeping a hand-curated config safe.
public enum SSHConfigWriter {
    public struct HostEntry: Sendable, Equatable {
        public var alias: String
        public var hostName: String
        public var user: String?
        public var port: Int?
        public var identityFile: String?
        public var proxyJump: String?

        public init(
            alias: String,
            hostName: String,
            user: String? = nil,
            port: Int? = nil,
            identityFile: String? = nil,
            proxyJump: String? = nil
        ) {
            self.alias = alias
            self.hostName = hostName
            self.user = user
            self.port = port
            self.identityFile = identityFile
            self.proxyJump = proxyJump
        }
    }

    public enum WriteError: LocalizedError {
        case invalidEntry(String)
        case duplicateAlias(String)

        public var errorDescription: String? {
            switch self {
            case .invalidEntry(let detail):
                return detail
            case .duplicateAlias(let alias):
                return "An SSH host named “\(alias)” already exists in your config."
            }
        }
    }

    /// Renders the `Host` block Burrow appends (also used for previews/tests).
    public static func render(_ entry: HostEntry) -> String {
        var lines = ["# Added by Burrow", "Host \(entry.alias)", "    HostName \(entry.hostName)"]
        if let user = entry.user, !user.isEmpty {
            lines.append("    User \(user)")
        }
        if let port = entry.port, port != 22 {
            lines.append("    Port \(port)")
        }
        if let identity = entry.identityFile, !identity.isEmpty {
            lines.append("    IdentityFile \(identity)")
        }
        if let jump = entry.proxyJump, !jump.isEmpty {
            lines.append("    ProxyJump \(jump)")
        }
        return lines.joined(separator: "\n")
    }

    /// Appends a host block to the config, creating ~/.ssh and the file (mode
    /// 0600) if needed. Rejects empty fields and aliases already present.
    public static func appendHost(_ entry: HostEntry, to url: URL = SSHConfigParser.defaultConfigURL()) throws {
        let alias = entry.alias.trimmingCharacters(in: .whitespacesAndNewlines)
        let hostName = entry.hostName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !alias.isEmpty, !alias.contains(where: { $0.isWhitespace }) else {
            throw WriteError.invalidEntry("A single-word host alias is required.")
        }
        guard !hostName.isEmpty, !hostName.contains(where: { $0.isWhitespace }) else {
            throw WriteError.invalidEntry("A host name (address) is required.")
        }
        if SSHConfigParser.parse(fileAt: url).contains(where: { $0.alias.lowercased() == alias.lowercased() }) {
            throw WriteError.duplicateAlias(alias)
        }

        let normalized = HostEntry(
            alias: alias,
            hostName: hostName,
            user: entry.user?.trimmingCharacters(in: .whitespacesAndNewlines),
            port: entry.port,
            identityFile: entry.identityFile,
            proxyJump: entry.proxyJump
        )

        let directory = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)

        let existing = (try? String(contentsOf: url, encoding: .utf8)) ?? ""
        var output = existing
        if !output.isEmpty && !output.hasSuffix("\n") {
            output += "\n"
        }
        output += "\n" + render(normalized) + "\n"

        try output.write(to: url, atomically: true, encoding: .utf8)
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
}
