import Foundation

public struct AppConfig: Codable, Sendable {
    public var version: Int
    public var tunnels: [TunnelConfig]
    public var gateways: [GatewayConfig]
    public var profiles: [Profile]
    public var twoFactorAccounts: [TwoFactorAccount]
    /// Which app to use for interactive SSH sessions: "auto", "iterm",
    /// "terminal", or "default".
    public var terminalApp: String

    public init(
        version: Int = 1,
        tunnels: [TunnelConfig] = [],
        gateways: [GatewayConfig] = [],
        profiles: [Profile] = [],
        twoFactorAccounts: [TwoFactorAccount] = [],
        terminalApp: String = "auto"
    ) {
        self.version = version
        self.tunnels = tunnels
        self.gateways = gateways
        self.profiles = profiles
        self.twoFactorAccounts = twoFactorAccounts
        self.terminalApp = terminalApp
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.version = try container.decodeIfPresent(Int.self, forKey: .version) ?? 1
        self.tunnels = try container.decodeIfPresent([TunnelConfig].self, forKey: .tunnels) ?? []
        self.gateways = try container.decodeIfPresent([GatewayConfig].self, forKey: .gateways) ?? []
        self.profiles = try container.decodeIfPresent([Profile].self, forKey: .profiles) ?? []
        self.twoFactorAccounts = try container.decodeIfPresent([TwoFactorAccount].self, forKey: .twoFactorAccounts) ?? []
        self.terminalApp = try container.decodeIfPresent(String.self, forKey: .terminalApp) ?? "auto"
    }
}

/// A TOTP enrollment for an SSH (or any) 2FA login. The shared secret lives in
/// the Keychain behind biometric access control; only these non-secret
/// generation params and routing hints are stored in the config file.
public struct TwoFactorAccount: Codable, Sendable, Identifiable, Equatable {
    public var id: String { name }
    /// Display name and Keychain key (e.g. "vista").
    public var name: String
    public var digits: Int
    public var period: Int
    /// "sha1" | "sha256" | "sha512".
    public var algorithm: String
    /// ssh host/alias to open a master connection to (Point 2). nil = code only.
    public var sshHost: String?
    /// How the askpass answers prompts: "codeOnly" (the keyboard-interactive
    /// prompt is just the OTP) or "passwordThenCode" (password, then OTP).
    public var strategy: String

    public var totpAlgorithm: TOTPSecret.Algorithm {
        TOTPSecret.Algorithm(rawValue: algorithm.lowercased()) ?? .sha1
    }

    public init(
        name: String,
        digits: Int = 6,
        period: Int = 30,
        algorithm: String = "sha1",
        sshHost: String? = nil,
        strategy: String = "codeOnly"
    ) {
        self.name = name
        self.digits = digits
        self.period = period
        self.algorithm = algorithm
        self.sshHost = sshHost
        self.strategy = strategy
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.name = try container.decode(String.self, forKey: .name)
        self.digits = try container.decodeIfPresent(Int.self, forKey: .digits) ?? 6
        self.period = try container.decodeIfPresent(Int.self, forKey: .period) ?? 30
        self.algorithm = try container.decodeIfPresent(String.self, forKey: .algorithm) ?? "sha1"
        self.sshHost = try container.decodeIfPresent(String.self, forKey: .sshHost)
        self.strategy = try container.decodeIfPresent(String.self, forKey: .strategy) ?? "codeOnly"
    }
}

/// A named bundle of tunnels (and gateways) started/stopped together.
public struct Profile: Codable, Sendable, Identifiable, Equatable {
    public var id: String { name }
    public var name: String
    public var tunnels: [String]
    public var gateways: [String]

    public init(name: String, tunnels: [String] = [], gateways: [String] = []) {
        self.name = name
        self.tunnels = tunnels
        self.gateways = gateways
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.name = try container.decode(String.self, forKey: .name)
        self.tunnels = try container.decodeIfPresent([String].self, forKey: .tunnels) ?? []
        self.gateways = try container.decodeIfPresent([String].self, forKey: .gateways) ?? []
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
    /// AnyConnect-only: the tunnel-group whose SAML sign-in to open
    /// (e.g. "cvpn-conn-profile"). Empty means the server's logon page is
    /// shown and the user picks the group there.
    public var samlGroup: String?
    /// Optional "host" or "host:port" reachable only when the VPN is truly up
    /// (e.g. "randi.cri.uchicago.edu:22"). Burrow probes it through the SOCKS
    /// proxy to tell a live tunnel from a stale ocproxy holding the port after
    /// the session died (sleep, network change). Empty disables the check.
    public var healthCheckHost: String?

    /// Parsed (host, port) of healthCheckHost; defaults the port to 443.
    public var healthCheckTarget: (host: String, port: Int)? {
        guard let raw = healthCheckHost?.trimmingCharacters(in: .whitespaces), !raw.isEmpty else {
            return nil
        }
        if let colon = raw.lastIndex(of: ":"),
           let port = Int(raw[raw.index(after: colon)...]) {
            let host = String(raw[..<colon])
            return host.isEmpty ? nil : (host, port)
        }
        return (raw, 443)
    }
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
        case samlGroup
        case healthCheckHost
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
        samlGroup: String? = nil,
        healthCheckHost: String? = nil,
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
        self.samlGroup = samlGroup
        self.healthCheckHost = healthCheckHost
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
        self.samlGroup = try container.decodeIfPresent(String.self, forKey: .samlGroup)
        self.healthCheckHost = try container.decodeIfPresent(String.self, forKey: .healthCheckHost)
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
    /// Shell command run when the tunnel becomes connected, with env vars
    /// BURROW_TUNNEL, BURROW_HOST, BURROW_LOCAL_PORT, BURROW_EVENT set.
    public var onConnect: String?
    /// Shell command run when the tunnel disconnects/fails.
    public var onDisconnect: String?

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
        gateway: String? = nil,
        onConnect: String? = nil,
        onDisconnect: String? = nil
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
        self.onConnect = onConnect
        self.onDisconnect = onDisconnect
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
