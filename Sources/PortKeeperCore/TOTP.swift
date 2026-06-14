import CryptoKit
import Foundation

/// A parsed TOTP enrollment: the shared secret plus its generation parameters.
/// Built from an `otpauth://totp/...` URI (what an authenticator QR encodes)
/// or from a raw base32 secret.
public struct TOTPSecret: Sendable, Equatable {
    public enum Algorithm: String, Sendable, Equatable {
        case sha1, sha256, sha512
    }

    public var secret: Data
    public var digits: Int
    public var period: Int
    public var algorithm: Algorithm
    public var label: String?
    public var issuer: String?

    public init(
        secret: Data,
        digits: Int = 6,
        period: Int = 30,
        algorithm: Algorithm = .sha1,
        label: String? = nil,
        issuer: String? = nil
    ) {
        self.secret = secret
        self.digits = digits
        self.period = period
        self.algorithm = algorithm
        self.label = label
        self.issuer = issuer
    }

    /// Parses `otpauth://totp/Issuer:account?secret=BASE32&digits=6&period=30&algorithm=SHA1&issuer=Issuer`.
    public static func parse(otpauthURI: String) -> TOTPSecret? {
        let trimmed = otpauthURI.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let components = URLComponents(string: trimmed),
              components.scheme?.lowercased() == "otpauth",
              (components.host?.lowercased() == "totp") else {
            return nil
        }
        let query = Dictionary(uniqueKeysWithValues: (components.queryItems ?? []).map { ($0.name.lowercased(), $0.value ?? "") })
        guard let base32 = query["secret"], let secret = base32Decode(base32), !secret.isEmpty else {
            return nil
        }

        let digits = query["digits"].flatMap(Int.init) ?? 6
        let period = query["period"].flatMap(Int.init) ?? 30
        let algorithm = Algorithm(rawValue: (query["algorithm"] ?? "sha1").lowercased()) ?? .sha1

        // Path is "/Issuer:account"; issuer query param wins if present.
        let label = components.path
            .trimmingCharacters(in: CharacterSet(charactersIn: "/"))
            .removingPercentEncoding
        let issuer = query["issuer"].flatMap { $0.isEmpty ? nil : $0 }

        return TOTPSecret(
            secret: secret,
            digits: digits >= 1 ? digits : 6,
            period: period >= 1 ? period : 30,
            algorithm: algorithm,
            label: (label?.isEmpty ?? true) ? nil : label,
            issuer: issuer
        )
    }

    /// Parses a raw base32 secret (e.g. a manual-entry key) with explicit params.
    public static func parse(
        base32: String,
        digits: Int = 6,
        period: Int = 30,
        algorithm: Algorithm = .sha1
    ) -> TOTPSecret? {
        guard let secret = base32Decode(base32), !secret.isEmpty else {
            return nil
        }
        return TOTPSecret(secret: secret, digits: digits, period: period, algorithm: algorithm)
    }

    /// Accepts either an otpauth URI or a bare base32 secret.
    public static func parse(_ input: String) -> TOTPSecret? {
        let trimmed = input.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.lowercased().hasPrefix("otpauth://") {
            return parse(otpauthURI: trimmed)
        }
        return parse(base32: trimmed)
    }

    /// RFC 4648 base32 decode; tolerates lowercase, spaces, dashes, padding.
    static func base32Decode(_ string: String) -> Data? {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        var lookup: [Character: Int] = [:]
        for (index, character) in alphabet.enumerated() {
            lookup[character] = index
        }

        let cleaned = string.uppercased().filter { $0 != "=" && !$0.isWhitespace && $0 != "-" }
        guard !cleaned.isEmpty else {
            return nil
        }

        var bits = 0
        var value = 0
        var output = Data()
        for character in cleaned {
            guard let symbol = lookup[character] else {
                return nil
            }
            value = (value << 5) | symbol
            bits += 5
            if bits >= 8 {
                bits -= 8
                output.append(UInt8((value >> bits) & 0xff))
            }
        }
        return output
    }
}

/// RFC 6238 time-based one-time password generation.
public enum TOTPGenerator {
    public static func code(for secret: TOTPSecret, at date: Date) -> String {
        let counter = UInt64(max(0, date.timeIntervalSince1970) / Double(secret.period))
        return code(secret: secret, counter: counter)
    }

    static func code(secret: TOTPSecret, counter: UInt64) -> String {
        var bigEndianCounter = counter.bigEndian
        let counterData = withUnsafeBytes(of: &bigEndianCounter) { Data($0) }
        let key = SymmetricKey(data: secret.secret)

        let digest: [UInt8]
        switch secret.algorithm {
        case .sha1:
            digest = Array(HMAC<Insecure.SHA1>.authenticationCode(for: counterData, using: key))
        case .sha256:
            digest = Array(HMAC<SHA256>.authenticationCode(for: counterData, using: key))
        case .sha512:
            digest = Array(HMAC<SHA512>.authenticationCode(for: counterData, using: key))
        }

        // Dynamic truncation (RFC 4226 §5.3).
        let offset = Int(digest[digest.count - 1] & 0x0f)
        let binary = (UInt32(digest[offset] & 0x7f) << 24)
            | (UInt32(digest[offset + 1]) << 16)
            | (UInt32(digest[offset + 2]) << 8)
            | UInt32(digest[offset + 3])

        var modulus: UInt32 = 1
        for _ in 0..<secret.digits {
            modulus &*= 10
        }
        let otp = binary % modulus
        return String(format: "%0\(secret.digits)u", otp)
    }
}
