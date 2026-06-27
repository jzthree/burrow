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

    /// Removes a host from the config, surgically: a single-alias `Host` stanza
    /// (and a preceding "# Added by Burrow" marker) is deleted whole; a stanza
    /// whose `Host` line lists several aliases only loses the one token, so the
    /// others keep their settings. Everything else is preserved verbatim.
    /// Hosts defined in Included files aren't in this file and throw notFound.
    public static func removeHost(alias: String, from url: URL = SSHConfigParser.defaultConfigURL()) throws {
        let target = alias.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !target.isEmpty else {
            throw WriteError.invalidEntry("No host alias given.")
        }
        guard let contents = try? String(contentsOf: url, encoding: .utf8) else {
            throw WriteError.invalidEntry("Couldn't read \(url.lastPathComponent).")
        }

        func keyword(_ line: String) -> String? {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty, !trimmed.hasPrefix("#") else { return nil }
            guard let range = trimmed.rangeOfCharacter(from: CharacterSet(charactersIn: " \t=")) else {
                return trimmed.lowercased()
            }
            return String(trimmed[..<range.lowerBound]).lowercased()
        }
        func hostTokens(_ line: String) -> [String] {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard let range = trimmed.rangeOfCharacter(from: CharacterSet(charactersIn: " \t=")) else {
                return []
            }
            return String(trimmed[range.upperBound...])
                .trimmingCharacters(in: CharacterSet(charactersIn: " \t="))
                .split(whereSeparator: { $0 == " " || $0 == "\t" })
                .map(String.init)
        }

        let lines = contents.components(separatedBy: "\n")
        var result: [String] = []
        var removedAny = false
        var index = 0
        while index < lines.count {
            let line = lines[index]
            let tokens = keyword(line) == "host" ? hostTokens(line) : []
            guard tokens.contains(where: { $0.lowercased() == target }) else {
                result.append(line)
                index += 1
                continue
            }

            removedAny = true
            if tokens.count > 1 {
                let indent = String(line.prefix { $0 == " " || $0 == "\t" })
                let remaining = tokens.filter { $0.lowercased() != target }
                result.append("\(indent)Host \(remaining.joined(separator: " "))")
                index += 1
            } else {
                // Drop the marker + the blank line Burrow inserted before it.
                if result.last?.trimmingCharacters(in: .whitespaces) == "# Added by Burrow" {
                    result.removeLast()
                }
                if result.last?.trimmingCharacters(in: .whitespaces).isEmpty == true {
                    result.removeLast()
                }
                index += 1
                while index < lines.count {
                    let next = keyword(lines[index])
                    if next == "host" || next == "match" { break }
                    index += 1
                }
            }
        }

        guard removedAny else {
            throw WriteError.invalidEntry("Host “\(alias)” wasn't found in \(url.lastPathComponent) (it may be in an Included file).")
        }
        try result.joined(separator: "\n").write(to: url, atomically: true, encoding: .utf8)
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
}
