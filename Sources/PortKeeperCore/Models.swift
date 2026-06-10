import Foundation

public struct AppConfig: Codable, Sendable {
    public var version: Int
    public var tunnels: [TunnelConfig]
    public var gateways: [GatewayConfig]

    public init(version: Int = 1, tunnels: [TunnelConfig] = [], gateways: [GatewayConfig] = []) {
        self.version = version
        self.tunnels = tunnels
        self.gateways = gateways
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.version = try container.decodeIfPresent(Int.self, forKey: .version) ?? 1
        self.tunnels = try container.decodeIfPresent([TunnelConfig].self, forKey: .tunnels) ?? []
        self.gateways = try container.decodeIfPresent([GatewayConfig].self, forKey: .gateways) ?? []
    }
}

/// A userspace VPN endpoint supervised by Burrow: openconnect + ocproxy expose
/// the VPN as a local SOCKS5 port with no tun device, no root, and no routing
/// table changes, so multiple gateways coexist with each other and with
/// system VPNs like Tailscale.
public struct GatewayConfig: Codable, Sendable, Identifiable, Equatable {
    public var id: String { name }
    public var name: String
    /// openconnect protocol id: "anyconnect", "gp", "pulse", "fortinet", ...
    public var vpnProtocol: String
    public var server: String
    public var user: String?
    public var socksPort: Int
    /// "password" (fed on stdin) or "saml" (browser-based single sign-on).
    public var authMode: String
    /// ssh host patterns routed through this gateway in the generated
    /// ssh include file (e.g. "*.university.edu", "172.18.*").
    public var sshHostPatterns: [String]
    public var extraArgs: [String]
    public var reconnectDelaySeconds: Int

    public var usesSAML: Bool {
        authMode.lowercased() == "saml"
    }

    enum CodingKeys: String, CodingKey {
        case name
        case vpnProtocol = "protocol"
        case server
        case user
        case socksPort
        case authMode
        case sshHostPatterns
        case extraArgs
        case reconnectDelaySeconds
    }

    public init(
        name: String,
        vpnProtocol: String,
        server: String,
        user: String? = nil,
        socksPort: Int,
        authMode: String = "password",
        sshHostPatterns: [String] = [],
        extraArgs: [String] = [],
        reconnectDelaySeconds: Int = 5
    ) {
        self.name = name
        self.vpnProtocol = vpnProtocol
        self.server = server
        self.user = user
        self.socksPort = socksPort
        self.authMode = authMode
        self.sshHostPatterns = sshHostPatterns
        self.extraArgs = extraArgs
        self.reconnectDelaySeconds = reconnectDelaySeconds
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.name = try container.decode(String.self, forKey: .name)
        self.vpnProtocol = try container.decodeIfPresent(String.self, forKey: .vpnProtocol) ?? "anyconnect"
        self.server = try container.decode(String.self, forKey: .server)
        self.user = try container.decodeIfPresent(String.self, forKey: .user)
        self.socksPort = try container.decode(Int.self, forKey: .socksPort)
        self.authMode = try container.decodeIfPresent(String.self, forKey: .authMode) ?? "password"
        self.sshHostPatterns = try container.decodeIfPresent([String].self, forKey: .sshHostPatterns) ?? []
        self.extraArgs = try container.decodeIfPresent([String].self, forKey: .extraArgs) ?? []
        self.reconnectDelaySeconds = try container.decodeIfPresent(Int.self, forKey: .reconnectDelaySeconds) ?? 5
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
    /// Name of the GatewayConfig this tunnel connects through, if any.
    public var gateway: String?

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
        extraSSHOptions: [String] = [],
        gateway: String? = nil
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
        self.gateway = gateway
    }
}

public struct ForwardSpec: Codable, Sendable, Equatable {
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
