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

    /// The directives that let one authenticated connection be reused by every
    /// later `ssh <alias>` — what "keeping a host warm" actually rests on.
    /// Without them ssh authenticates, exits, and leaves nothing behind: the
    /// user types their password and 2FA code again every single time, and
    /// Burrow can only report that it "signed in but kept no master".
    ///
    /// ControlPersist is a duration rather than `yes` so a master that nothing
    /// is using eventually retires on its own.
    public static let multiplexingDirectives: [(name: String, value: String)] = [
        ("ControlMaster", "auto"),
        ("ControlPath", "~/.ssh/burrow/cm-%r@%h:%p"),
        ("ControlPersist", "8h"),
    ]

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
        for directive in multiplexingDirectives {
            lines.append("    \(directive.name) \(directive.value)")
        }
        return lines.joined(separator: "\n")
    }

    /// Adds whichever multiplexing directives `alias`'s stanza is missing,
    /// leaving any it already sets alone (a hand-tuned ControlPath stays).
    /// Returns the names it added — empty when the host was already set up.
    ///
    /// This is the repair for "signed in but kept no master": the fix is three
    /// lines of ssh config, and telling someone to go add them by hand is not
    /// an answer a tool should give when it can just do it.
    @discardableResult
    public static func enableMultiplexing(
        alias: String,
        in url: URL = SSHConfigParser.defaultConfigURL()
    ) throws -> [String] {
        let target = alias.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !target.isEmpty else {
            throw WriteError.invalidEntry("No host alias given.")
        }
        guard let contents = try? String(contentsOf: url, encoding: .utf8) else {
            throw WriteError.invalidEntry("Couldn't read \(url.lastPathComponent).")
        }

        var lines = contents.components(separatedBy: "\n")
        let targetLower = target.lowercased()
        guard let hostLineIndex = lines.firstIndex(where: {
            keyword($0) == "host" && hostTokens($0).contains { $0.lowercased() == targetLower }
        }) else {
            throw WriteError.invalidEntry("Host “\(alias)” wasn't found in \(url.lastPathComponent) (it may be in an Included file).")
        }

        var bodyEnd = hostLineIndex + 1
        while bodyEnd < lines.count {
            let kw = keyword(lines[bodyEnd])
            if kw == "host" || kw == "match" { break }
            bodyEnd += 1
        }
        let bodyRange = (hostLineIndex + 1)..<bodyEnd
        var body = Array(lines[bodyRange])
        let indent = body
            .first(where: { !$0.trimmingCharacters(in: .whitespaces).isEmpty })
            .map { String($0.prefix { $0 == " " || $0 == "\t" }) } ?? "    "

        // Insert after the stanza's last directive, before any trailing blank
        // lines that separate it from the next Host block.
        var insertionPoint = body.count
        while insertionPoint > 0, body[insertionPoint - 1].trimmingCharacters(in: .whitespaces).isEmpty {
            insertionPoint -= 1
        }

        var added: [String] = []
        for directive in multiplexingDirectives where !body.contains(where: { keyword($0) == directive.name.lowercased() }) {
            body.insert("\(indent)\(directive.name) \(directive.value)", at: insertionPoint)
            insertionPoint += 1
            added.append(directive.name)
        }
        guard !added.isEmpty else { return [] }

        try ensureControlPathDirectory()
        lines.replaceSubrange(bodyRange, with: body)
        try writeConfigText(lines.joined(separator: "\n"), to: url)
        return added
    }

    /// ssh won't create the directory a ControlPath lives in; without it every
    /// connection fails to open the socket and silently keeps no master.
    public static func ensureControlPathDirectory(fileManager: FileManager = .default) throws {
        let directory = fileManager.homeDirectoryForCurrentUser
            .appendingPathComponent(".ssh", isDirectory: true)
            .appendingPathComponent("burrow", isDirectory: true)
        try fileManager.createDirectory(at: directory, withIntermediateDirectories: true)
        try? fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
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
        let existingAliases = SSHConfigParser.parse(fileAt: url)
            .flatMap { $0.allAliases }
            .map { $0.lowercased() }
        if existingAliases.contains(alias.lowercased()) {
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
        // The rendered block sets a ControlPath; its directory has to exist
        // before the first connection or no master is ever kept.
        try? ensureControlPathDirectory()

        let existing = (try? String(contentsOf: url, encoding: .utf8)) ?? ""
        var output = existing
        if !output.isEmpty && !output.hasSuffix("\n") {
            output += "\n"
        }
        output += "\n" + render(normalized) + "\n"

        try writeConfigText(output, to: url)
    }

    /// Writes the config through a symlinked path (dotfiles setups commonly
    /// symlink ~/.ssh/config). An atomic write aimed at the symlink itself
    /// would replace the link with a plain file and silently orphan the
    /// user's real config.
    private static func writeConfigText(_ text: String, to url: URL) throws {
        let destination = url.resolvingSymlinksInPath()
        try text.write(to: destination, atomically: true, encoding: .utf8)
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: destination.path)
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
        try writeConfigText(result.joined(separator: "\n"), to: url)
    }

    /// Edits an existing host's HostName / User / Port *in place*, touching only
    /// those directive lines inside the alias's stanza and leaving every other
    /// line (ControlMaster, ProxyJump, comments, formatting) verbatim. A nil/empty
    /// user or a nil/22 port removes that directive. Hosts in Included files
    /// aren't in this file and throw notFound.
    public static func editHost(
        alias: String,
        hostName: String?,
        user: String?,
        port: Int?,
        in url: URL = SSHConfigParser.defaultConfigURL()
    ) throws {
        let target = alias.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !target.isEmpty else {
            throw WriteError.invalidEntry("No host alias given.")
        }
        let newHostName = hostName?.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let newHostName, !newHostName.isEmpty, !newHostName.contains(where: { $0.isWhitespace }) else {
            throw WriteError.invalidEntry("A host name (address) is required.")
        }
        let newUser = user?.trimmingCharacters(in: .whitespacesAndNewlines)
        if let newUser, newUser.contains(where: { $0.isWhitespace }) {
            throw WriteError.invalidEntry("A user name can't contain spaces.")
        }
        guard let contents = try? String(contentsOf: url, encoding: .utf8) else {
            throw WriteError.invalidEntry("Couldn't read \(url.lastPathComponent).")
        }

        var lines = contents.components(separatedBy: "\n")
        let targetLower = target.lowercased()
        guard let hostLineIndex = lines.firstIndex(where: {
            keyword($0) == "host" && hostTokens($0).contains { $0.lowercased() == targetLower }
        }) else {
            throw WriteError.invalidEntry("Host “\(alias)” wasn't found in \(url.lastPathComponent) (it may be in an Included file).")
        }

        // The stanza body runs from just after the Host line to the next
        // Host/Match line (or end of file).
        var bodyEnd = hostLineIndex + 1
        while bodyEnd < lines.count {
            let kw = keyword(lines[bodyEnd])
            if kw == "host" || kw == "match" { break }
            bodyEnd += 1
        }
        let bodyRange = (hostLineIndex + 1)..<bodyEnd
        var body = Array(lines[bodyRange])

        // Reuse an existing directive's indent so inserted lines match the stanza.
        let indent = body
            .first(where: { !$0.trimmingCharacters(in: .whitespaces).isEmpty })
            .map { String($0.prefix { $0 == " " || $0 == "\t" }) } ?? "    "

        func setDirective(_ name: String, value: String?) {
            let lower = name.lowercased()
            if let existing = body.firstIndex(where: { keyword($0) == lower }) {
                if let value {
                    let lineIndent = String(body[existing].prefix { $0 == " " || $0 == "\t" })
                    body[existing] = "\(lineIndent)\(name) \(value)"
                } else {
                    body.remove(at: existing)
                }
            } else if let value {
                body.insert("\(indent)\(name) \(value)", at: 0)
            }
        }

        // Insert in reverse so a fresh stanza ends up HostName, User, Port.
        setDirective("Port", value: (port != nil && port != 22) ? String(port!) : nil)
        setDirective("User", value: (newUser?.isEmpty == false) ? newUser : nil)
        setDirective("HostName", value: newHostName)

        lines.replaceSubrange(bodyRange, with: body)
        try writeConfigText(lines.joined(separator: "\n"), to: url)
    }

    private static func keyword(_ line: String) -> String? {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty, !trimmed.hasPrefix("#") else { return nil }
        guard let range = trimmed.rangeOfCharacter(from: CharacterSet(charactersIn: " \t=")) else {
            return trimmed.lowercased()
        }
        return String(trimmed[..<range.lowerBound]).lowercased()
    }

    private static func hostTokens(_ line: String) -> [String] {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        guard let range = trimmed.rangeOfCharacter(from: CharacterSet(charactersIn: " \t=")) else {
            return []
        }
        return String(trimmed[range.upperBound...])
            .trimmingCharacters(in: CharacterSet(charactersIn: " \t="))
            .split(whereSeparator: { $0 == " " || $0 == "\t" })
            .map(String.init)
    }
}
