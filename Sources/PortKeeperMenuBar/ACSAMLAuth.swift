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
final class AnyConnectSAMLAuthenticator: NSObject, WKNavigationDelegate, NSWindowDelegate, WKScriptMessageHandler {
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

    // Recording (learn a sign-in recipe by watching the user do it once).
    private var recording = false
    private var recordedSteps: [SAMLSignInRecipe.Step] = []
    private var recordPage = 0
    /// After a successful *recording*, the learned recipe and the password the
    /// user typed (for the caller to store in the Keychain). Never persisted here.
    private(set) var capturedRecipe: SAMLSignInRecipe?
    private(set) var capturedPassword: String?

    init(gateway: GatewayConfig) {
        self.gateway = gateway
    }

    /// Opens the sign-in and watches for the session cookie. `interactive`
    /// shows the window for the user to complete (and, if `record`, learns the
    /// recipe). A non-interactive autoconnect with no learned recipe can't be
    /// completed silently, so it reports `.interactionRequired` at once (the
    /// gateway shows "click Connect") rather than opening a blind, unclosable
    /// off-screen window. Recipe-based silent replay is handled by the caller.
    func begin(interactive: Bool = true, record: Bool = false, completion: @escaping (Result<String, Error>) -> Void) {
        self.completion = completion
        self.recording = record

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
        if record {
            // Watch which controls the user fills/clicks so we can learn a recipe
            // to replay this sign-in later. Injected into every frame (Duo can be
            // in an iframe); it captures element *locators*, and the password
            // value once, but nothing else.
            configuration.userContentController.add(self, name: "burrowRec")
            configuration.userContentController.addUserScript(
                WKUserScript(source: Self.recorderScript, injectionTime: .atDocumentEnd, forMainFrameOnly: false)
            )
        }
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
        if recording {
            recordPage += 1   // each finished navigation is a new page of the flow
        }
        checkForSessionCookie()
    }

    // MARK: - Recording

    /// Captured while the user signs in once: each control they touch, as a
    /// robust locator, in order. The password value is captured separately so it
    /// can go to the Keychain — it is never written into the recipe.
    func userContentController(_ controller: WKUserContentController, didReceive message: WKScriptMessage) {
        guard recording, message.name == "burrowRec",
              let body = message.body as? [String: Any],
              let action = body["action"] as? String,
              let raw = body["field"] as? [String: Any] else {
            return
        }
        let field = SAMLSignInRecipe.Field(
            tag: (raw["tag"] as? String) ?? "",
            type: nonEmpty(raw["type"]),
            name: nonEmpty(raw["name"]),
            elementID: nonEmpty(raw["id"]),
            autocomplete: nonEmpty(raw["autocomplete"]),
            ariaLabel: nonEmpty(raw["ariaLabel"]),
            placeholder: nonEmpty(raw["placeholder"]),
            text: nonEmpty(raw["text"])
        )
        let mapped: SAMLSignInRecipe.Action?
        switch action {
        case "password":
            capturedPassword = (body["value"] as? String)
            mapped = .fillPassword
        case "code": mapped = .fillCode
        case "check": mapped = .check
        case "click": mapped = .click
        default: mapped = nil
        }
        guard let mapped else { return }
        let step = SAMLSignInRecipe.Step(page: recordPage, action: mapped, field: field)
        // Collapse an immediate duplicate (repeated focus/blur or double click).
        if recordedSteps.last == step { return }
        recordedSteps.append(step)
    }

    private func nonEmpty(_ any: Any?) -> String? {
        guard let s = any as? String, !s.isEmpty else { return nil }
        return s
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
        if recording, case .success = result, !recordedSteps.isEmpty {
            capturedRecipe = SAMLSignInRecipe(
                steps: recordedSteps,
                recordedAt: ISO8601DateFormatter().string(from: Date())
            )
        }
        self.completion = nil
        cookiePollTask?.cancel()
        cookiePollTask = nil
        if recording {
            webView?.configuration.userContentController.removeScriptMessageHandler(forName: "burrowRec")
        }
        if closeWindow {
            window?.delegate = nil
            window?.close()
        }
        window = nil
        webView?.navigationDelegate = nil
        webView = nil
        completion(result)
    }

    // Injected into every frame while recording: reports which control the user
    // fills, ticks, or clicks (as a locator), plus the password value once.
    private static let recorderScript = """
    (function(){
      if (window.__burrowRec) return; window.__burrowRec = 1;
      function post(m){ try { window.webkit.messageHandlers.burrowRec.postMessage(m); } catch(e){} }
      function labelText(el){ try { return (el.labels && el.labels.length) ? (el.labels[0].innerText||'') : ''; } catch(e){ return ''; } }
      function attr(el,n){ try { return el.getAttribute(n) || ''; } catch(e){ return ''; } }
      function desc(el){
        return { tag:(el.tagName||'').toLowerCase(), type:(el.type||''), name:(el.name||''), id:(el.id||''),
                 autocomplete:attr(el,'autocomplete'), ariaLabel:attr(el,'aria-label'), placeholder:(el.placeholder||''),
                 text:((el.innerText || el.value || labelText(el) || '')+'').trim().slice(0,60) };
      }
      var otpRe = /(one-time|onetime|otp|passcode|mfa|verifica|token|\\bcode\\b)/i;
      document.addEventListener('change', function(e){
        var el=e.target; if(!el||!el.tagName) return;
        if(el.tagName==='INPUT' && el.type==='checkbox' && el.checked) post({action:'check', field:desc(el)});
        if(el.tagName==='INPUT' && el.type==='password' && el.value) post({action:'password', value:el.value, field:desc(el)});
      }, true);
      document.addEventListener('blur', function(e){
        var el=e.target; if(!el||!el.tagName||el.tagName!=='INPUT') return;
        if(el.type!=='password' && el.type!=='checkbox' && el.value &&
           otpRe.test((el.name||'')+' '+(el.id||'')+' '+attr(el,'autocomplete')+' '+attr(el,'aria-label')+' '+(el.placeholder||'')))
          post({action:'code', field:desc(el)});
      }, true);
      document.addEventListener('click', function(e){
        var el=e.target && e.target.closest && e.target.closest('button, input[type=submit], input[type=button], a[role=button], [role=button]');
        if(el) post({action:'click', field:desc(el)});
      }, true);
    })();
    """
}
