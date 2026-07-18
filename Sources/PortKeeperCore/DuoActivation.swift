import Foundation
import Security

/// Duo Mobile "activation" enrollment.
///
/// A `duo://` code (what Duo's setup QR encodes) is **not** a shared secret — it
/// is a single-use device-activation code of the form
/// `<activation_code>-<base64(api_host)>`. To turn it into usable passcodes an
/// app must do a one-time HTTPS exchange with Duo: it posts a freshly generated
/// RSA public key to `https://<host>/push/v2/activation/<code>`, and Duo returns
/// an `hotp_secret`. Duo's offline passcodes are then plain **HOTP** (SHA-1,
/// 6 digits, counter-based) with that secret's ASCII bytes as the key — which is
/// exactly RFC 4226, so `passcode` matches the RFC 4226 test vectors.
public enum DuoActivation {
    public struct ParsedCode: Sendable, Equatable {
        public let activationCode: String
        public let host: String
    }

    public struct Enrollment: Sendable, Equatable {
        public let hotpSecret: String
        public let pkey: String?
        public let customerName: String?
    }

    public enum DuoError: LocalizedError {
        case invalidCode
        case keyGeneration(String)
        case network(String)
        case badResponse(String)
        case duoRejected(String)

        public var errorDescription: String? {
            switch self {
            case .invalidCode:
                return "That doesn't look like a Duo activation code (expected duo://…)."
            case .keyGeneration(let detail):
                return "Couldn't generate the device key: \(detail)"
            case .network(let detail):
                return "Couldn't reach Duo: \(detail)"
            case .badResponse(let detail):
                return "Unexpected reply from Duo: \(detail)"
            case .duoRejected(let detail):
                return "Duo rejected the activation: \(detail)"
            }
        }
    }

    /// Parses `duo://<activation_code>-<base64 host>` (also tolerates the bare
    /// `<code>-<b64host>` with no scheme).
    public static func parse(_ input: String) -> ParsedCode? {
        var text = input.trimmingCharacters(in: .whitespacesAndNewlines)
        if let range = text.range(of: "duo://", options: [.caseInsensitive, .anchored]) {
            text = String(text[range.upperBound...])
        }
        guard let dash = text.firstIndex(of: "-") else { return nil }
        let code = String(text[..<dash])
        let hostPart = String(text[text.index(after: dash)...])
        guard !code.isEmpty, !hostPart.isEmpty else { return nil }
        guard let host = base64URLDecodedString(hostPart), !host.isEmpty else { return nil }
        return ParsedCode(activationCode: code, host: host)
    }

    /// The current Duo offline passcode: HOTP-SHA1, 6 digits, key = the ASCII
    /// bytes of `hotpSecret`, moving factor = `counter`.
    public static func passcode(hotpSecret: String, counter: Int, digits: Int = 6) -> String {
        let secret = TOTPSecret(
            secret: Data(hotpSecret.utf8),
            digits: digits,
            period: 30,
            algorithm: .sha1
        )
        return TOTPGenerator.code(secret: secret, counter: UInt64(max(0, counter)))
    }

    /// Performs the one-time activation exchange and returns the `hotp_secret`.
    /// This provisions Burrow as a Duo device and consumes the (single-use) code.
    public static func activate(_ parsed: ParsedCode, session: URLSession = .shared) async throws -> Enrollment {
        let pubKeyPEM = try generateDevicePublicKeyPEM()

        guard let url = URL(string: "https://\(parsed.host)/push/v2/activation/\(parsed.activationCode)") else {
            throw DuoError.invalidCode
        }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.httpBody = formEncode([
            "pubkey": pubKeyPEM,
            "pkpush": "rsa-sha512",
            "jailbroken": "false",
            "architecture": "arm64",
            "region": "US",
            "app_id": "com.duosecurity.duomobile",
            "full_disk_encryption": "true",
            "passcode_status": "true",
            "platform": "Android",
            "app_version": "4.59.0",
            "app_build_number": "459010",
            "version": "13",
            "manufacturer": "unknown",
            "model": "Burrow",
            "language": "en",
            "security_patch_level": "2023-08-01",
        ])

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: request)
        } catch {
            throw DuoError.network(error.localizedDescription)
        }

        let body = String(data: data, encoding: .utf8) ?? ""
        guard let decoded = try? JSONDecoder().decode(DuoResponse.self, from: data) else {
            let status = (response as? HTTPURLResponse)?.statusCode ?? 0
            throw DuoError.badResponse("HTTP \(status): \(body.prefix(200))")
        }
        guard decoded.stat.uppercased() == "OK", let inner = decoded.response else {
            throw DuoError.duoRejected(decoded.message ?? "\(decoded.message_detail ?? body.prefix(200).description)")
        }
        guard let secret = inner.hotp_secret, !secret.isEmpty else {
            throw DuoError.badResponse("no hotp_secret in the reply — this code may already be used.")
        }
        return Enrollment(hotpSecret: secret, pkey: inner.pkey, customerName: inner.customer_name)
    }

    // MARK: - Response

    private struct DuoResponse: Decodable {
        let stat: String
        let message: String?
        let message_detail: String?
        let response: Inner?
        struct Inner: Decodable {
            let hotp_secret: String?
            let pkey: String?
            let customer_name: String?
        }
    }

    // MARK: - Crypto / encoding helpers

    /// Generates a 2048-bit RSA keypair and returns the public key as an X.509
    /// SubjectPublicKeyInfo PEM ("-----BEGIN PUBLIC KEY-----"), which is what
    /// Duo's activation endpoint expects.
    private static func generateDevicePublicKeyPEM() throws -> String {
        var error: Unmanaged<CFError>?
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048,
        ]
        guard let priv = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw DuoError.keyGeneration((error?.takeRetainedValue()).map { "\($0)" } ?? "SecKeyCreateRandomKey failed")
        }
        guard let pub = SecKeyCopyPublicKey(priv) else {
            throw DuoError.keyGeneration("no public key")
        }
        guard let pkcs1 = SecKeyCopyExternalRepresentation(pub, &error) as Data? else {
            throw DuoError.keyGeneration((error?.takeRetainedValue()).map { "\($0)" } ?? "export failed")
        }
        let spki = wrapRSAPublicKeyInSPKI(pkcs1)
        return pemEncode(spki, label: "PUBLIC KEY")
    }

    /// SecKey exports an RSA public key as PKCS#1 (RSAPublicKey); wrap it in the
    /// X.509 SubjectPublicKeyInfo structure Duo expects.
    private static func wrapRSAPublicKeyInSPKI(_ pkcs1: Data) -> Data {
        // AlgorithmIdentifier { rsaEncryption, NULL }.
        let algorithmIdentifier: [UInt8] = [
            0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
            0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
        ]
        var bitString: [UInt8] = [0x03]
        bitString += derLength(pkcs1.count + 1)
        bitString.append(0x00)
        bitString += [UInt8](pkcs1)

        var body = algorithmIdentifier
        body += bitString

        var sequence: [UInt8] = [0x30]
        sequence += derLength(body.count)
        sequence += body
        return Data(sequence)
    }

    private static func derLength(_ length: Int) -> [UInt8] {
        if length < 0x80 { return [UInt8(length)] }
        var value = length
        var bytes: [UInt8] = []
        while value > 0 {
            bytes.insert(UInt8(value & 0xff), at: 0)
            value >>= 8
        }
        return [UInt8(0x80 | bytes.count)] + bytes
    }

    private static func pemEncode(_ der: Data, label: String) -> String {
        let base64 = der.base64EncodedString()
        var lines = ["-----BEGIN \(label)-----"]
        var index = base64.startIndex
        while index < base64.endIndex {
            let end = base64.index(index, offsetBy: 64, limitedBy: base64.endIndex) ?? base64.endIndex
            lines.append(String(base64[index..<end]))
            index = end
        }
        lines.append("-----END \(label)-----")
        return lines.joined(separator: "\n")
    }

    private static func base64URLDecodedString(_ input: String) -> String? {
        var base64 = input.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while base64.count % 4 != 0 { base64.append("=") }
        guard let data = Data(base64Encoded: base64) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private static func formEncode(_ params: [String: String]) -> Data {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        let pairs = params.map { key, value -> String in
            let k = key.addingPercentEncoding(withAllowedCharacters: allowed) ?? key
            let v = value.addingPercentEncoding(withAllowedCharacters: allowed) ?? value
            return "\(k)=\(v)"
        }
        return pairs.joined(separator: "&").data(using: .utf8) ?? Data()
    }
}
