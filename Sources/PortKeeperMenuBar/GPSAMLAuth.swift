import AppKit
import Foundation
import PortKeeperCore
import WebKit

/// Browser-based SAML sign-in for GlobalProtect gateways, equivalent to
/// gp-saml-gui: fetch the SAML request from the VPN's prelogin endpoint, let
/// the user authenticate in a WebKit window, and capture the prelogin cookie
/// that openconnect then uses as its password. The web view uses the default
/// (persistent) data store, so the IdP session usually survives reconnects
/// and the window closes after a brief flash.
@MainActor
final class GPSAMLAuthenticator: NSObject, WKNavigationDelegate, NSWindowDelegate {
    struct SAMLResult {
        let username: String
        let cookie: String
        let usergroup: String
    }

    enum SAMLError: LocalizedError {
        case preloginFailed(String)
        case cancelled

        var errorDescription: String? {
            switch self {
            case .preloginFailed(let message):
                return message
            case .cancelled:
                return "SAML sign-in was cancelled."
            }
        }
    }

    private let gateway: GatewayConfig
    private var window: NSWindow?
    private var webView: WKWebView?
    private var completion: ((Result<SAMLResult, Error>) -> Void)?
    private var headerUsername: String?

    init(gateway: GatewayConfig) {
        self.gateway = gateway
    }

    func begin(completion: @escaping (Result<SAMLResult, Error>) -> Void) {
        self.completion = completion
        Task { @MainActor in
            do {
                let prelogin = try await fetchPrelogin()
                presentWebView(with: prelogin)
            } catch {
                finish(.failure(error))
            }
        }
    }

    func cancel() {
        finish(.failure(SAMLError.cancelled))
    }

    // MARK: - Prelogin

    private struct PreloginResponse {
        let method: String       // "REDIRECT" or "POST"
        let request: String      // decoded URL or HTML
        let cookieUsergroup: String
    }

    private func fetchPrelogin() async throws -> PreloginResponse {
        // Gateway interface first (cookie: prelogin-cookie), portal second
        // (cookie: portal-userauthcookie); deployments vary.
        let attempts: [(path: String, usergroup: String)] = [
            ("/ssl-vpn/prelogin.esp", "gateway:prelogin-cookie"),
            ("/global-protect/prelogin.esp", "portal:portal-userauthcookie"),
        ]

        var lastError = "No SAML prelogin response from \(gateway.server)."
        for attempt in attempts {
            guard let url = URL(string: "https://\(gateway.server)\(attempt.path)") else {
                continue
            }
            var request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
            request.setValue("PAN GlobalProtect", forHTTPHeaderField: "User-Agent")
            request.httpBody = Data("tmp=tmp&kerberos-support=yes&ipv6-support=yes&clientVer=4100&clientos=Mac".utf8)

            do {
                let (data, _) = try await URLSession.shared.data(for: request)
                let body = String(data: data, encoding: .utf8) ?? ""

                guard let methodTag = firstTag("saml-auth-method", in: body),
                      let requestTag = firstTag("saml-request", in: body) else {
                    if let status = firstTag("status", in: body), status.lowercased() != "success" {
                        let message = firstTag("msg", in: body) ?? status
                        lastError = "Prelogin (\(attempt.path)): \(message)"
                    } else {
                        lastError = "Prelogin (\(attempt.path)): no SAML request in response — the server may not use SAML on this interface."
                    }
                    continue
                }

                guard let decoded = Data(base64Encoded: requestTag, options: .ignoreUnknownCharacters)
                    .flatMap({ String(data: $0, encoding: .utf8) }) else {
                    lastError = "Prelogin (\(attempt.path)): could not decode SAML request."
                    continue
                }

                return PreloginResponse(method: methodTag.uppercased(), request: decoded, cookieUsergroup: attempt.usergroup)
            } catch {
                lastError = "Prelogin (\(attempt.path)): \(error.localizedDescription)"
                continue
            }
        }

        throw SAMLError.preloginFailed(lastError)
    }

    private func firstTag(_ tag: String, in text: String) -> String? {
        guard let openRange = text.range(of: "<\(tag)>"),
              let closeRange = text.range(of: "</\(tag)>", range: openRange.upperBound..<text.endIndex) else {
            return nil
        }
        let value = String(text[openRange.upperBound..<closeRange.lowerBound])
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return value.isEmpty ? nil : value
    }

    // MARK: - Web view

    private func presentWebView(with prelogin: PreloginResponse) {
        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = .default()
        let webView = WKWebView(frame: NSRect(x: 0, y: 0, width: 480, height: 640), configuration: configuration)
        webView.navigationDelegate = self
        webView.customUserAgent = "PAN GlobalProtect"
        self.webView = webView

        let window = NSWindow(contentViewController: NSViewController())
        window.contentView = webView
        window.styleMask = [.titled, .closable, .resizable]
        window.title = "Sign in — \(gateway.name)"
        window.setContentSize(NSSize(width: 480, height: 640))
        window.isReleasedWhenClosed = false
        window.level = .floating
        window.delegate = self
        window.center()
        self.window = window
        self.pendingUsergroup = prelogin.cookieUsergroup

        if prelogin.method == "POST" {
            webView.loadHTMLString(prelogin.request, baseURL: URL(string: "https://\(gateway.server)/"))
        } else if let url = URL(string: prelogin.request) {
            webView.load(URLRequest(url: url))
        } else {
            finish(.failure(SAMLError.preloginFailed("SAML request was not a loadable URL.")))
            return
        }

        MenuBarPopover.dismiss()
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    private var pendingUsergroup = "gateway:prelogin-cookie"

    func webView(
        _ webView: WKWebView,
        decidePolicyFor navigationResponse: WKNavigationResponse,
        decisionHandler: @escaping (WKNavigationResponsePolicy) -> Void
    ) {
        if let httpResponse = navigationResponse.response as? HTTPURLResponse {
            var headers: [String: String] = [:]
            for (key, value) in httpResponse.allHeaderFields {
                if let key = key as? String, let value = value as? String {
                    headers[key.lowercased()] = value
                }
            }
            if let username = headers["saml-username"] {
                headerUsername = username
            }
            if let cookie = headers["prelogin-cookie"] {
                deliver(cookie: cookie, usergroup: "gateway:prelogin-cookie")
            } else if let cookie = headers["portal-userauthcookie"] {
                deliver(cookie: cookie, usergroup: "portal:portal-userauthcookie")
            }
        }
        decisionHandler(.allow)
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        // Some IdPs return the tokens in the final page body instead of headers.
        webView.evaluateJavaScript("document.documentElement.outerHTML") { [weak self] result, _ in
            guard let self, self.completion != nil, let html = result as? String else {
                return
            }
            if let username = self.firstTag("saml-username", in: html) {
                self.headerUsername = username
            }
            if let cookie = self.firstTag("prelogin-cookie", in: html) {
                self.deliver(cookie: cookie, usergroup: "gateway:prelogin-cookie")
            } else if let cookie = self.firstTag("portal-userauthcookie", in: html) {
                self.deliver(cookie: cookie, usergroup: "portal:portal-userauthcookie")
            }
        }
    }

    func windowWillClose(_ notification: Notification) {
        if completion != nil {
            finish(.failure(SAMLError.cancelled), closeWindow: false)
        }
    }

    private func deliver(cookie: String, usergroup: String) {
        guard completion != nil else {
            return
        }
        let username = headerUsername ?? gateway.user ?? ""
        guard !username.isEmpty else {
            finish(.failure(SAMLError.preloginFailed("SAML sign-in finished but no username was returned; set a User on the gateway as a fallback.")))
            return
        }
        finish(.success(SAMLResult(username: username, cookie: cookie, usergroup: usergroup)))
    }

    private func finish(_ result: Result<SAMLResult, Error>, closeWindow: Bool = true) {
        guard let completion else {
            return
        }
        self.completion = nil
        if closeWindow {
            window?.delegate = nil
            window?.close()
        }
        window = nil
        webView?.navigationDelegate = nil
        webView = nil
        completion(result)
    }
}
