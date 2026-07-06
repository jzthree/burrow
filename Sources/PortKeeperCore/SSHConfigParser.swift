import Darwin
import Foundation

public struct SSHConfigHost: Sendable, Equatable {
    public var alias: String
    /// Extra names on the same `Host` line (e.g. an FQDN listed next to a short
    /// name). They target the same stanza, so the host is shown as a single
    /// entry keyed on `alias`, not one row per name.
    public var additionalAliases: [String]
    public var hostName: String?
    public var user: String?
    public var port: Int?
    public var identityFile: String?
    public var proxyJump: String?
    public var forwards: [ForwardSpec]

    public init(
        alias: String,
        additionalAliases: [String] = [],
        hostName: String? = nil,
        user: String? = nil,
        port: Int? = nil,
        identityFile: String? = nil,
        proxyJump: String? = nil,
        forwards: [ForwardSpec] = []
    ) {
        self.alias = alias
        self.additionalAliases = additionalAliases
        self.hostName = hostName
        self.user = user
        self.port = port
        self.identityFile = identityFile
        self.proxyJump = proxyJump
        self.forwards = forwards
    }

    public var effectiveHost: String {
        hostName ?? alias
    }

    /// Every name this stanza answers to — the primary alias and any extras.
    public var allAliases: [String] {
        [alias] + additionalAliases
    }

    /// Whether `candidate` is this stanza's primary or any additional alias.
    public func matchesAlias(_ candidate: String) -> Bool {
        alias == candidate || additionalAliases.contains(candidate)
    }
}

public enum SSHConfigParser {
    public static func defaultConfigURL() -> URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".ssh", isDirectory: true)
            .appendingPathComponent("config", isDirectory: false)
    }

    /// Parses an OpenSSH client config into one entry per concrete `Host`
    /// stanza. A `Host` line with several names becomes a single entry keyed
    /// on the first name, with the rest kept in `additionalAliases`.
    /// Wildcard-only stanzas (`Host *`, `Host *.example.edu`) don't become
    /// entries, but their directives are folded into every concrete host they
    /// match — first-obtained-wins across stanzas, like ssh itself — so a
    /// `User`/`IdentityFile` set under `Host *` shows up on each host.
    public static func parse(fileAt url: URL = defaultConfigURL()) -> [SSHConfigHost] {
        var visited: Set<String> = []
        let lines = collectLines(fileAt: url, visited: &visited)
        return parse(lines: lines)
    }

    public static func parse(contents: String) -> [SSHConfigHost] {
        parse(lines: contents.components(separatedBy: .newlines))
    }

    private struct Stanza {
        var patterns: [String]
        var directives: [(keyword: String, value: String)] = []
    }

    private static func parse(lines: [String]) -> [SSHConfigHost] {
        // Pass 1: split into stanzas, in file order. `Match` blocks get an
        // empty pattern list — their conditions aren't evaluated here, so
        // they contribute nothing rather than something wrong.
        var stanzas: [Stanza] = []
        var current: Stanza?
        for rawLine in lines {
            guard let (keyword, value) = parseLine(rawLine) else {
                continue
            }
            if keyword == "host" {
                if let current {
                    stanzas.append(current)
                }
                current = Stanza(patterns: tokenize(value))
                continue
            }
            if keyword == "match" {
                if let current {
                    stanzas.append(current)
                }
                current = Stanza(patterns: [])
                continue
            }
            current?.directives.append((keyword, value))
        }
        if let current {
            stanzas.append(current)
        }

        // Pass 2: one entry per concrete stanza, folding in every stanza that
        // matches the alias (including wildcard defaults). `apply` only sets
        // unset fields, which gives ssh's first-obtained-wins semantics.
        var hosts: [SSHConfigHost] = []
        var seenAliases: Set<String> = []
        for stanza in stanzas {
            let concrete = stanza.patterns
                .filter { !$0.contains("*") && !$0.contains("?") && !$0.hasPrefix("!") }
            guard let primary = concrete.first, !seenAliases.contains(primary) else {
                continue
            }
            seenAliases.insert(primary)
            var host = SSHConfigHost(alias: primary, additionalAliases: Array(concrete.dropFirst()))
            for candidate in stanzas where stanzaMatches(candidate.patterns, alias: primary) {
                for directive in candidate.directives {
                    apply(keyword: directive.keyword, value: directive.value, to: &host)
                }
            }
            hosts.append(host)
        }
        return hosts
    }

    /// ssh-style pattern-list match against a host alias: `*`/`?` glob, and a
    /// matching `!pattern` vetoes the whole stanza regardless of other
    /// patterns.
    private static func stanzaMatches(_ patterns: [String], alias: String) -> Bool {
        var matched = false
        for pattern in patterns {
            if pattern.hasPrefix("!") {
                if fnmatch(String(pattern.dropFirst()), alias, 0) == 0 {
                    return false
                }
            } else if fnmatch(pattern, alias, 0) == 0 {
                matched = true
            }
        }
        return matched
    }

    private static func apply(keyword: String, value: String, to host: inout SSHConfigHost) {
        switch keyword {
        case "hostname":
            if host.hostName == nil {
                host.hostName = value
            }
        case "user":
            if host.user == nil {
                host.user = value
            }
        case "port":
            if host.port == nil {
                host.port = Int(value)
            }
        case "identityfile":
            if host.identityFile == nil {
                host.identityFile = tokenize(value).first
            }
        case "proxyjump":
            if host.proxyJump == nil, value.lowercased() != "none" {
                host.proxyJump = value
            }
        case "localforward":
            if let forward = parseForward(kind: .local, value: value) {
                host.forwards.append(forward)
            }
        case "remoteforward":
            if let forward = parseForward(kind: .remote, value: value) {
                host.forwards.append(forward)
            }
        case "dynamicforward":
            if let forward = parseDynamicForward(value: value) {
                host.forwards.append(forward)
            }
        default:
            break
        }
    }

    private static func parseForward(kind: ForwardSpec.Kind, value: String) -> ForwardSpec? {
        let tokens = tokenize(value)
        guard tokens.count == 2 else {
            return nil
        }

        guard let (bindAddress, listenPort) = parseListenSpec(tokens[0]) else {
            return nil
        }

        let destination = tokens[1]
        guard let separatorIndex = destination.lastIndex(of: ":"),
              let destinationPort = Int(destination[destination.index(after: separatorIndex)...]) else {
            return nil
        }
        let destinationHost = String(destination[..<separatorIndex])
        guard !destinationHost.isEmpty else {
            return nil
        }

        return ForwardSpec(
            kind: kind,
            bindAddress: bindAddress,
            listenPort: listenPort,
            destinationHost: destinationHost,
            destinationPort: destinationPort
        )
    }

    private static func parseDynamicForward(value: String) -> ForwardSpec? {
        guard let (bindAddress, listenPort) = parseListenSpec(value) else {
            return nil
        }
        return ForwardSpec(kind: .dynamic, bindAddress: bindAddress, listenPort: listenPort)
    }

    private static func parseListenSpec(_ token: String) -> (bindAddress: String?, listenPort: Int)? {
        if let port = Int(token) {
            return (nil, port)
        }
        guard let separatorIndex = token.lastIndex(of: ":"),
              let port = Int(token[token.index(after: separatorIndex)...]) else {
            return nil
        }
        let bind = String(token[..<separatorIndex])
        return (bind.isEmpty ? nil : bind, port)
    }

    private static func parseLine(_ rawLine: String) -> (keyword: String, value: String)? {
        let line = rawLine.trimmingCharacters(in: .whitespaces)
        guard !line.isEmpty, !line.hasPrefix("#") else {
            return nil
        }

        let separators = CharacterSet(charactersIn: " \t=")
        guard let separatorRange = line.rangeOfCharacter(from: separators) else {
            return nil
        }

        let keyword = String(line[..<separatorRange.lowerBound]).lowercased()
        let value = String(line[separatorRange.upperBound...])
            .trimmingCharacters(in: CharacterSet(charactersIn: " \t="))
        guard !value.isEmpty else {
            return nil
        }
        return (keyword, value)
    }

    private static func tokenize(_ value: String) -> [String] {
        value
            .split(whereSeparator: { $0 == " " || $0 == "\t" })
            .map { token in
                let trimmed = String(token)
                if trimmed.hasPrefix("\"") && trimmed.hasSuffix("\"") && trimmed.count >= 2 {
                    return String(trimmed.dropFirst().dropLast())
                }
                return trimmed
            }
            .filter { !$0.isEmpty }
    }

    private static func collectLines(fileAt url: URL, visited: inout Set<String>) -> [String] {
        let path = url.path
        guard !visited.contains(path), visited.count < 32 else {
            return []
        }
        visited.insert(path)

        guard let contents = try? String(contentsOf: url, encoding: .utf8) else {
            return []
        }

        var lines: [String] = []
        for rawLine in contents.components(separatedBy: .newlines) {
            if let (keyword, value) = parseLine(rawLine), keyword == "include" {
                for pattern in tokenize(value) {
                    for includedURL in resolveIncludePattern(pattern, relativeTo: url) {
                        lines.append(contentsOf: collectLines(fileAt: includedURL, visited: &visited))
                    }
                }
            } else {
                lines.append(rawLine)
            }
        }
        return lines
    }

    private static func resolveIncludePattern(_ pattern: String, relativeTo configURL: URL) -> [URL] {
        let expanded = NSString(string: pattern).expandingTildeInPath
        let basePath: String
        if expanded.hasPrefix("/") {
            basePath = expanded
        } else {
            basePath = configURL.deletingLastPathComponent().appendingPathComponent(expanded).path
        }

        guard basePath.contains("*") || basePath.contains("?") || basePath.contains("[") else {
            return [URL(fileURLWithPath: basePath)]
        }

        let directory = (basePath as NSString).deletingLastPathComponent
        let filePattern = (basePath as NSString).lastPathComponent
        guard let entries = try? FileManager.default.contentsOfDirectory(atPath: directory) else {
            return []
        }

        return entries
            .filter { fnmatch(filePattern, $0, 0) == 0 }
            .sorted()
            .map { URL(fileURLWithPath: directory).appendingPathComponent($0) }
    }
}
