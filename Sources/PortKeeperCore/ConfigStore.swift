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

    public func upsert(_ tunnel: TunnelConfig) throws {
        var config = try load()
        if let index = config.tunnels.firstIndex(where: { $0.name == tunnel.name }) {
            config.tunnels[index] = tunnel
        } else {
            config.tunnels.append(tunnel)
        }
        config.tunnels.sort { $0.name < $1.name }
        try save(config)
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
