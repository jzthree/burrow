import AppKit
import Foundation
import PortKeeperCore
import WebKit

/// A browser sign-in that can be cancelled when its gateway is stopped.
@MainActor
protocol SAMLAuthenticating: AnyObject {
    func cancel()
}

extension GPSAMLAuthenticator: SAMLAuthenticating {}
extension AnyConnectSAMLAuthenticator: SAMLAuthenticating {}

/// Browser-based SAML sign-in for AnyConnect (Cisco ASA) gateways.
///
/// Modern ASAs refuse to start SAML inside openconnect's own handshake (the
/// embedded flow is gated on Cisco's STRAP key exchange, which openconnect
/// does not implement) and fall back to a password form that SSO-only
/// accounts can never satisfy. The clientless web logon, however, still
/// drives the full SAML dance for any browser. So: load that logon flow in a
/// WebKit window, let the user authenticate at the IdP, and capture the
/// `webvpn` session cookie the ASA sets on success — openconnect then skips
/// authentication entirely via --cookie-on-stdin. The persistent web data
/// store keeps the IdP session, so a re-auth is usually a quick window flash.
@MainActor
final class AnyConnectSAMLAuthenticator: NSObject, WKNavigationDelegate, NSWindowDelegate {
    enum ACSAMLError: LocalizedError {
        case cancelled
        case interactionRequired
        case badServer

        var errorDescription: String? {
            switch self {
            case .cancelled:
                return "SAML sign-in was cancelled."
            case .interactionRequired:
                return "SAML sign-in needs attention — click Connect"
            case .badServer:
                return "Gateway server is not a valid host name."
            }
        }
    }

    private let gateway: GatewayConfig
    private var window: NSWindow?
    private var webView: WKWebView?
    private var completion: ((Result<String, Error>) -> Void)?
    private var cookiePollTask: Task<Void, Never>?

    init(gateway: GatewayConfig) {
        self.gateway = gateway
    }

    /// Opens the sign-in window and watches for the session cookie.
    /// `interactive == false` (headless launch auto-start) skips the window
    /// and reports that a sign-in is needed, mirroring the GP flow.
    func begin(interactive: Bool = true, completion: @escaping (Result<String, Error>) -> Void) {
        self.completion = completion
        guard interactive else {
            finish(.failure(ACSAMLError.interactionRequired))
            return
        }

        // A configured group jumps straight into its SAML redirect; without
        // one the ASA logon page lets the user pick the group and sign in.
        let path: String
        if let group = gateway.samlGroup, !group.isEmpty {
            let encoded = group.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? group
            path = "/+CSCOE+/saml/sp/login?tgname=\(encoded)"
        } else {
            path = "/+CSCOE+/logon.html"
        }
        guard let url = URL(string: "https://\(gateway.server)\(path)") else {
            finish(.failure(ACSAMLError.badServer))
            return
        }

        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = .default()
        let webView = WKWebView(frame: NSRect(x: 0, y: 0, width: 480, height: 640), configuration: configuration)
        webView.navigationDelegate = self
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

        // A webvpn cookie left over from a previous session would be captured
        // instantly even though it is almost certainly dead (openconnect's BYE
        // tears the session down server-side). Clear it, then sign in fresh.
        let cookieStore = configuration.websiteDataStore.httpCookieStore
        let host = gateway.server.lowercased()
        cookieStore.getAllCookies { [weak self] cookies in
            guard let self else {
                return
            }
            let stale = cookies.filter {
                $0.name == "webvpn"
                    && host.hasSuffix($0.domain.trimmingCharacters(in: CharacterSet(charactersIn: ".")).lowercased())
            }
            let group = DispatchGroup()
            for cookie in stale {
                group.enter()
                cookieStore.delete(cookie) { group.leave() }
            }
            group.notify(queue: .main) {
                guard self.completion != nil, let webView = self.webView else {
                    return
                }
                webView.load(URLRequest(url: url))
                self.startCookieWatch()
            }
        }

        MenuBarPopover.dismiss()
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    func cancel() {
        finish(.failure(ACSAMLError.cancelled))
    }

    // MARK: - Cookie capture

    /// The Set-Cookie can land on a redirect hop with no page navigation to
    /// hook, so poll the cookie store while the window is up; didFinish below
    /// is an immediate-check fast path.
    private func startCookieWatch() {
        cookiePollTask = Task { @MainActor [weak self] in
            while !Task.isCancelled {
                self?.checkForSessionCookie()
                try? await Task.sleep(for: .milliseconds(700))
            }
        }
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        checkForSessionCookie()
    }

    private func checkForSessionCookie() {
        guard completion != nil, let webView else {
            return
        }
        let host = gateway.server.lowercased()
        webView.configuration.websiteDataStore.httpCookieStore.getAllCookies { [weak self] cookies in
            guard let self, self.completion != nil else {
                return
            }
            // The ASA names its session token `webvpn`. Pre-auth requests set
            // only helpers (webvpnlogin, webvpnLang, CSRFtoken), so require a
            // substantive value before treating the sign-in as complete.
            let sessionCookie = cookies.first { cookie in
                cookie.name == "webvpn"
                    && host.hasSuffix(cookie.domain.trimmingCharacters(in: CharacterSet(charactersIn: ".")).lowercased())
                    && cookie.value.count >= 16
            }
            if let sessionCookie {
                self.finish(.success(sessionCookie.value))
            }
        }
    }

    // MARK: - Window lifecycle

    func windowWillClose(_ notification: Notification) {
        if completion != nil {
            finish(.failure(ACSAMLError.cancelled), closeWindow: false)
        }
    }

    private func finish(_ result: Result<String, Error>, closeWindow: Bool = true) {
        guard let completion else {
            return
        }
        self.completion = nil
        cookiePollTask?.cancel()
        cookiePollTask = nil
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
