import Darwin
import Foundation

public struct ConfigStore: Sendable {
    public let configURL: URL
    private let legacyConfigURL: URL?

    public init(configURL: URL? = nil) {
        if let configURL {
            self.configURL = configURL
            self.legacyConfigURL = nil
        } else {
            let baseURL = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            self.configURL = baseURL
                .appendingPathComponent("Burrow", isDirectory: true)
                .appendingPathComponent("config.json", isDirectory: false)
            self.legacyConfigURL = baseURL
                .appendingPathComponent("PortKeeper", isDirectory: true)
                .appendingPathComponent("config.json", isDirectory: false)
        }
    }

    @discardableResult
    public func ensureExists() throws -> URL {
        let directory = configURL.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        if !FileManager.default.fileExists(atPath: configURL.path) {
            if let legacyConfigURL, FileManager.default.fileExists(atPath: legacyConfigURL.path) {
                try FileManager.default.copyItem(at: legacyConfigURL, to: configURL)
            } else {
                try save(AppConfig())
            }
        }
        return configURL
    }

    public func load() throws -> AppConfig {
        try ensureExists()
        let data = try Data(contentsOf: configURL)
        do {
            return try JSONDecoder().decode(AppConfig.self, from: data)
        } catch let error as DecodingError {
            throw ConfigFileError(decodingError: error, fileName: configURL.lastPathComponent)
        }
    }

    public func save(_ config: AppConfig) throws {
        let directory = configURL.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try encodeForDisk(config).write(to: configURL, options: .atomic)
    }

    /// A locked read-modify-write cycle. The app and the CLI share one
    /// config.json; without the lock, two concurrent mutations both read the
    /// old file and the second save silently drops the first one's change.
    /// Use this (not load + save) for any edit of the current config.
    /// Writes only when the transform actually changed something, so no-op
    /// mutations don't wake the app's config-file watcher.
    public func mutate<T>(_ transform: (inout AppConfig) throws -> T) throws -> T {
        try withExclusiveLock {
            var config = try load()
            let before = try encodeForDisk(config)
            let result = try transform(&config)
            let after = try encodeForDisk(config)
            if after != before {
                try after.write(to: configURL, options: .atomic)
            }
            return result
        }
    }

    private func encodeForDisk(_ config: AppConfig) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return try encoder.encode(config)
    }

    /// Holds an exclusive advisory flock on a sidecar file for the duration
    /// of `body`. Best-effort: if the lock file can't be opened, `body` still
    /// runs — an unlocked edit beats making the config immutable.
    private func withExclusiveLock<T>(_ body: () throws -> T) throws -> T {
        try? FileManager.default.createDirectory(
            at: configURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        let lockPath = configURL.appendingPathExtension("lock").path
        let descriptor = open(lockPath, O_CREAT | O_RDWR, 0o600)
        var locked = false
        if descriptor >= 0 {
            locked = flock(descriptor, LOCK_EX) == 0
        }
        defer {
            if locked {
                flock(descriptor, LOCK_UN)
            }
            if descriptor >= 0 {
                close(descriptor)
            }
        }
        return try body()
    }

    public func upsert(_ tunnel: TunnelConfig, replacing originalName: String? = nil) throws {
        try mutate { config in
            let replacementName = originalName ?? tunnel.name
            if let index = config.tunnels.firstIndex(where: { $0.name == replacementName }) {
                config.tunnels[index] = tunnel
                for duplicateIndex in config.tunnels.indices.reversed() where duplicateIndex != index && config.tunnels[duplicateIndex].name == tunnel.name {
                    config.tunnels.remove(at: duplicateIndex)
                }
            } else if let index = config.tunnels.firstIndex(where: { $0.name == tunnel.name }) {
                config.tunnels[index] = tunnel
            } else {
                config.tunnels.append(tunnel)
            }

            // Profiles reference tunnels by name; a rename must follow.
            if let originalName, originalName != tunnel.name {
                for index in config.profiles.indices {
                    config.profiles[index].tunnels = config.profiles[index].tunnels.map {
                        $0 == originalName ? tunnel.name : $0
                    }
                }
            }
        }
    }

    public func upsertGateway(_ gateway: GatewayConfig, replacing originalName: String? = nil) throws {
        try mutate { config in
            let replacementName = originalName ?? gateway.name
            if let index = config.gateways.firstIndex(where: { $0.name == replacementName }) {
                config.gateways[index] = gateway
                for duplicateIndex in config.gateways.indices.reversed() where duplicateIndex != index && config.gateways[duplicateIndex].name == gateway.name {
                    config.gateways.remove(at: duplicateIndex)
                }
            } else if let index = config.gateways.firstIndex(where: { $0.name == gateway.name }) {
                config.gateways[index] = gateway
            } else {
                config.gateways.append(gateway)
            }

            // Tunnels and profiles reference gateways by name; a rename must
            // follow or they're left pointing at a gateway that no longer exists.
            if let originalName, originalName != gateway.name {
                for index in config.tunnels.indices where config.tunnels[index].gateway == originalName {
                    config.tunnels[index].gateway = gateway.name
                }
                for index in config.profiles.indices {
                    config.profiles[index].gateways = config.profiles[index].gateways.map {
                        $0 == originalName ? gateway.name : $0
                    }
                }
            }
        }
    }

    @discardableResult
    public func removeGateway(name: String) throws -> Bool {
        try mutate { config in
            let originalCount = config.gateways.count
            config.gateways.removeAll { $0.name == name }
            return config.gateways.count != originalCount
        }
    }

    public func upsertProfile(_ profile: Profile, replacing originalName: String? = nil) throws {
        try mutate { config in
            let replacementName = originalName ?? profile.name
            if let index = config.profiles.firstIndex(where: { $0.name == replacementName }) {
                config.profiles[index] = profile
                for duplicateIndex in config.profiles.indices.reversed() where duplicateIndex != index && config.profiles[duplicateIndex].name == profile.name {
                    config.profiles.remove(at: duplicateIndex)
                }
            } else if let index = config.profiles.firstIndex(where: { $0.name == profile.name }) {
                config.profiles[index] = profile
            } else {
                config.profiles.append(profile)
            }
        }
    }

    @discardableResult
    public func removeProfile(name: String) throws -> Bool {
        try mutate { config in
            let originalCount = config.profiles.count
            config.profiles.removeAll { $0.name == name }
            return config.profiles.count != originalCount
        }
    }

    public func remove(name: String) throws -> Bool {
        try mutate { config in
            let originalCount = config.tunnels.count
            config.tunnels.removeAll { $0.name == name }
            return config.tunnels.count != originalCount
        }
    }

    public func upsertTwoFactorAccount(_ account: TwoFactorAccount, replacing originalName: String? = nil) throws {
        try mutate { config in
            let replacementName = originalName ?? account.name
            if let index = config.twoFactorAccounts.firstIndex(where: { $0.name == replacementName }) {
                config.twoFactorAccounts[index] = account
                for duplicate in config.twoFactorAccounts.indices.reversed()
                where duplicate != index && config.twoFactorAccounts[duplicate].name == account.name {
                    config.twoFactorAccounts.remove(at: duplicate)
                }
            } else if let index = config.twoFactorAccounts.firstIndex(where: { $0.name == account.name }) {
                config.twoFactorAccounts[index] = account
            } else {
                config.twoFactorAccounts.append(account)
            }
        }
    }

    @discardableResult
    public func removeTwoFactorAccount(name: String) throws -> Bool {
        try mutate { config in
            let originalCount = config.twoFactorAccounts.count
            config.twoFactorAccounts.removeAll { $0.name == name }
            return config.twoFactorAccounts.count != originalCount
        }
    }
}

/// Wraps a DecodingError from config.json into something a person can act
/// on: names the offending field path instead of Foundation's generic
/// "data couldn't be read" message. Hand-editing the JSON is a supported
/// workflow, so the error text is part of the UI.
public struct ConfigFileError: LocalizedError {
    public let message: String

    init(decodingError: DecodingError, fileName: String) {
        func path(_ codingPath: [CodingKey]) -> String {
            var rendered = ""
            for key in codingPath {
                if let index = key.intValue {
                    rendered += "[\(index)]"
                } else {
                    rendered += rendered.isEmpty ? key.stringValue : ".\(key.stringValue)"
                }
            }
            return rendered.isEmpty ? "top level" : rendered
        }

        switch decodingError {
        case .keyNotFound(let key, let context):
            message = "\(fileName): missing required field '\(key.stringValue)' at \(path(context.codingPath))"
        case .typeMismatch(let type, let context):
            message = "\(fileName): wrong type at \(path(context.codingPath)) — expected \(type)"
        case .valueNotFound(let type, let context):
            message = "\(fileName): null value at \(path(context.codingPath)) — expected \(type)"
        case .dataCorrupted(let context):
            let detail = context.codingPath.isEmpty
                ? context.debugDescription
                : "invalid value at \(path(context.codingPath))"
            message = "\(fileName): not valid JSON — \(detail)"
        @unknown default:
            message = "\(fileName): could not be parsed"
        }
    }

    public var errorDescription: String? { message }
}
