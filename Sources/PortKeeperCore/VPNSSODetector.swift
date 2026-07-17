import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Detects whether a VPN server signs in through browser SSO (SAML), so the
/// gateway editor can steer users away from password mode when it can't work.
/// Anonymous, credential-free probes of public login endpoints only.
public enum VPNSSODetector {
    /// The probe's read on a server. `.inconclusive` (network error, unknown
    /// protocol, odd response) must never trigger UI — only a definitive
    /// `.sso` should steer the user. `suggestedGroup` is set when the SSO
    /// hand-off was found via a tunnel group discovered on the logon page,
    /// so the editor can fill the SAML Group field too.
    public enum Verdict: Sendable, Equatable {
        case sso(suggestedGroup: String?)
        case noSSODetected
        case inconclusive
    }

    /// Probes `server` for a browser-SSO sign-in.
    ///
    /// - AnyConnect (ASA): `GET /+CSCOE+/saml/sp/login[?tgname=…]` answers with
    ///   a redirect to the IdP (Okta, Shibboleth, Entra, …) when the tunnel
    ///   group uses SAML; the plain logon page stays on the same host.
    /// - GlobalProtect: `GET /global-protect/prelogin.esp` returns XML that
    ///   names a saml auth method when SSO is in use.
    public static func probe(server: String, vpnProtocol: String, samlGroup: String?) async -> Verdict {
        let host = server.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !host.isEmpty else { return .inconclusive }
        switch vpnProtocol.lowercased() {
        case "anyconnect":
            return await probeAnyConnect(host: host, group: samlGroup)
        case "gp":
            return await probeGlobalProtect(host: host)
        default:
            return .inconclusive
        }
    }

    private static func probeAnyConnect(host: String, group: String?) async -> Verdict {
        let trimmedGroup = group?.trimmingCharacters(in: .whitespacesAndNewlines)
        // 1. A configured group is checked directly.
        if let trimmedGroup, !trimmedGroup.isEmpty {
            switch await checkAnyConnectGroup(host: host, group: trimmedGroup) {
            case .sso: return .sso(suggestedGroup: nil)   // their group already works
            case .noSSODetected: break                    // fall through to discovery
            case .inconclusive: return .inconclusive
            }
        }
        // 2. The bare endpoint covers ASAs whose default group is SAML.
        switch await checkAnyConnectGroup(host: host, group: nil) {
        case .sso: return .sso(suggestedGroup: nil)
        case .inconclusive: return .inconclusive
        case .noSSODetected: break
        }
        // 3. The logon page lists the server's tunnel groups; probe each for the
        //    SAML hand-off and suggest the first that has one. This is how a
        //    server whose *default* group is password-only (but whose real
        //    profile is SSO) still gets detected from just a hostname.
        for candidate in await discoverTunnelGroups(host: host).prefix(6) {
            if case .sso = await checkAnyConnectGroup(host: host, group: candidate) {
                return .sso(suggestedGroup: candidate)
            }
        }
        return .noSSODetected
    }

    /// Whether one tunnel group's SAML endpoint hands off to an IdP.
    private static func checkAnyConnectGroup(host: String, group: String?) async -> Verdict {
        var path = "/+CSCOE+/saml/sp/login"
        if let group, !group.isEmpty {
            let encoded = group.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? group
            path += "?tgname=\(encoded)"
        }
        guard let url = URL(string: "https://\(host)\(path)") else { return .inconclusive }
        guard let (response, _) = await fetchWithoutRedirects(url) else { return .inconclusive }
        // A redirect to another host is the SAML hand-off to the IdP; anything
        // same-host (logon page, error page) is not SSO for this group.
        if (300..<400).contains(response.statusCode),
           let location = response.value(forHTTPHeaderField: "Location"),
           let target = URL(string: location, relativeTo: url)?.host,
           target.caseInsensitiveCompare(url.host ?? host) != .orderedSame {
            return .sso(suggestedGroup: group)
        }
        if (200..<400).contains(response.statusCode) {
            return .noSSODetected
        }
        return .inconclusive
    }

    /// Tunnel-group names from the ASA logon page's group picker
    /// (`<select id="group_list">…<option value="…">`), HTML-entity decoded,
    /// in page order (the page's preselected group comes first anyway).
    static func discoverTunnelGroups(host: String) async -> [String] {
        guard let url = URL(string: "https://\(host)/+CSCOE+/logon.html"),
              let (response, data) = await fetchWithoutRedirects(url),
              response.statusCode == 200,
              let body = String(data: data, encoding: .utf8) else {
            return []
        }
        return parseTunnelGroups(fromLogonPage: body)
    }

    /// Exposed for tests: pulls option values out of the group_list select.
    public static func parseTunnelGroups(fromLogonPage body: String) -> [String] {
        guard let selectStart = body.range(of: "id=\"group_list\""),
              let selectEnd = body.range(of: "</select>", range: selectStart.upperBound..<body.endIndex) else {
            return []
        }
        let block = body[selectStart.upperBound..<selectEnd.lowerBound]
        var groups: [String] = []
        var searchStart = block.startIndex
        while let marker = block.range(of: "option value=\"", range: searchStart..<block.endIndex) {
            guard let quote = block.range(of: "\"", range: marker.upperBound..<block.endIndex) else { break }
            let raw = String(block[marker.upperBound..<quote.lowerBound])
            let decoded = decodeHTMLEntities(raw)
            if !decoded.isEmpty && !groups.contains(decoded) {
                groups.append(decoded)
            }
            searchStart = quote.upperBound
        }
        return groups
    }

    /// Minimal entity decoding for ASA-encoded option values (numeric entities
    /// like `&#x2D;` plus the common named few).
    static func decodeHTMLEntities(_ text: String) -> String {
        var result = ""
        var rest = Substring(text)
        while let amp = rest.firstIndex(of: "&") {
            result += rest[..<amp]
            rest = rest[amp...]
            guard let semi = rest.firstIndex(of: ";"), rest.distance(from: rest.startIndex, to: semi) <= 8 else {
                result += String(rest.first!)
                rest = rest.dropFirst()
                continue
            }
            let entity = rest[rest.index(after: rest.startIndex)..<semi]
            var replacement: String?
            if entity.hasPrefix("#x") || entity.hasPrefix("#X") {
                replacement = UInt32(entity.dropFirst(2), radix: 16).flatMap(Unicode.Scalar.init).map(String.init)
            } else if entity.hasPrefix("#") {
                replacement = UInt32(entity.dropFirst()).flatMap(Unicode.Scalar.init).map(String.init)
            } else {
                replacement = ["amp": "&", "lt": "<", "gt": ">", "quot": "\"", "apos": "'"][String(entity)]
            }
            if let replacement {
                result += replacement
                rest = rest[rest.index(after: semi)...]
            } else {
                result += String(rest.first!)
                rest = rest.dropFirst()
            }
        }
        result += rest
        return result
    }

    private static func probeGlobalProtect(host: String) async -> Verdict {
        guard let url = URL(string: "https://\(host)/global-protect/prelogin.esp?tmp=tmp&clientos=Mac") else {
            return .inconclusive
        }
        guard let (response, data) = await fetchWithoutRedirects(url), response.statusCode == 200,
              let body = String(data: data, encoding: .utf8)?.lowercased() else {
            return .inconclusive
        }
        if body.contains("saml-auth-method") || body.contains("saml-request") {
            return .sso(suggestedGroup: nil)
        }
        // A prelogin answer that names another method is a real "no".
        if body.contains("<status>success</status>") || body.contains("authentication-message") {
            return .noSSODetected
        }
        return .inconclusive
    }

    /// GET without following redirects (the redirect *is* the signal).
    private static func fetchWithoutRedirects(_ url: URL) async -> (HTTPURLResponse, Data)? {
        var request = URLRequest(url: url)
        request.timeoutInterval = 6
        request.httpMethod = "GET"
        let session = URLSession(configuration: .ephemeral, delegate: RedirectBlocker(), delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }
        guard let (data, response) = try? await session.data(for: request),
              let http = response as? HTTPURLResponse else {
            return nil
        }
        return (http, data)
    }

    private final class RedirectBlocker: NSObject, URLSessionTaskDelegate {
        func urlSession(
            _ session: URLSession,
            task: URLSessionTask,
            willPerformHTTPRedirection response: HTTPURLResponse,
            newRequest request: URLRequest,
            completionHandler: @escaping (URLRequest?) -> Void
        ) {
            completionHandler(nil)
        }
    }
}
