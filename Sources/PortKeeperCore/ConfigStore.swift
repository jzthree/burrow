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
        return try JSONDecoder().decode(AppConfig.self, from: data)
    }

    public func save(_ config: AppConfig) throws {
        let directory = configURL.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(config)
        try data.write(to: configURL, options: .atomic)
    }

    public func upsert(_ tunnel: TunnelConfig, replacing originalName: String? = nil) throws {
        var config = try load()
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
        try save(config)
    }

    public func upsertGateway(_ gateway: GatewayConfig, replacing originalName: String? = nil) throws {
        var config = try load()
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
        try save(config)
    }

    @discardableResult
    public func removeGateway(name: String) throws -> Bool {
        var config = try load()
        let originalCount = config.gateways.count
        config.gateways.removeAll { $0.name == name }
        if config.gateways.count != originalCount {
            try save(config)
            return true
        }
        return false
    }

    public func upsertProfile(_ profile: Profile, replacing originalName: String? = nil) throws {
        var config = try load()
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
        try save(config)
    }

    @discardableResult
    public func removeProfile(name: String) throws -> Bool {
        var config = try load()
        let originalCount = config.profiles.count
        config.profiles.removeAll { $0.name == name }
        if config.profiles.count != originalCount {
            try save(config)
            return true
        }
        return false
    }

    public func remove(name: String) throws -> Bool {
        var config = try load()
        let originalCount = config.tunnels.count
        config.tunnels.removeAll { $0.name == name }
        if config.tunnels.count != originalCount {
            try save(config)
            return true
        }
        return false
    }
}
