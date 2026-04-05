import Foundation

public struct AppConfig: Codable, Sendable {
    public var version: Int
    public var tunnels: [TunnelConfig]

    public init(version: Int = 1, tunnels: [TunnelConfig] = []) {
        self.version = version
        self.tunnels = tunnels
    }
}

public struct TunnelConfig: Codable, Sendable, Identifiable {
    public var id: String { name }
    public var name: String
    public var host: String
    public var user: String?
    public var sshPort: Int
    public var identityFile: String?
    public var jumpHost: String?
    public var forwards: [ForwardSpec]
    public var serverAliveInterval: Int
    public var serverAliveCountMax: Int
    public var reconnectDelaySeconds: Int
    public var enabled: Bool
    public var extraSSHOptions: [String]

    public init(
        name: String,
        host: String,
        user: String? = nil,
        sshPort: Int = 22,
        identityFile: String? = nil,
        jumpHost: String? = nil,
        forwards: [ForwardSpec],
        serverAliveInterval: Int = 30,
        serverAliveCountMax: Int = 3,
        reconnectDelaySeconds: Int = 5,
        enabled: Bool = true,
        extraSSHOptions: [String] = []
    ) {
        self.name = name
        self.host = host
        self.user = user
        self.sshPort = sshPort
        self.identityFile = identityFile
        self.jumpHost = jumpHost
        self.forwards = forwards
        self.serverAliveInterval = serverAliveInterval
        self.serverAliveCountMax = serverAliveCountMax
        self.reconnectDelaySeconds = reconnectDelaySeconds
        self.enabled = enabled
        self.extraSSHOptions = extraSSHOptions
    }
}

public struct ForwardSpec: Codable, Sendable {
    public enum Kind: String, Codable, Sendable {
        case local
        case remote
        case dynamic
    }

    public var kind: Kind
    public var bindAddress: String?
    public var listenPort: Int
    public var destinationHost: String?
    public var destinationPort: Int?

    public init(
        kind: Kind,
        bindAddress: String? = nil,
        listenPort: Int,
        destinationHost: String? = nil,
        destinationPort: Int? = nil
    ) {
        self.kind = kind
        self.bindAddress = bindAddress
        self.listenPort = listenPort
        self.destinationHost = destinationHost
        self.destinationPort = destinationPort
    }
}
