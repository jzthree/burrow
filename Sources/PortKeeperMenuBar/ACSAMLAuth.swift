import AppKit
import Foundation
import PortKeeperCore
import WebKit

/// A browser sign-in that can be cancelled when its gateway is stopped.
@MainActor
protocol SAMLAuthenticating: AnyObject {
    func cancel()
    /// False for a silent background attempt — a user's explicit Connect click
    /// outranks one and may cancel-and-replace it with a visible window.
    var isInteractive: Bool { get }
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
    private(set) var isInteractive = true
    /// Bounds a silent attempt: past this, the flow evidently needs the user.
    private var silentDeadlineTask: Task<Void, Never>?
    /// Silent replay: the learned recipe driven with the Keychain password, so
    /// an expired IdP session reconnects with zero clicks.
    private var replayTask: Task<Void, Never>?
    private var replayPassword: String?
    /// Generates a live TOTP code when a fillCode step runs (codes expire, so
    /// they can't be captured up front the way the password is).
    private var replayCodeProvider: (@MainActor () async -> String?)?

    // Recording (learn a sign-in recipe by watching the user do it once).
    private var recording = false
    private var recordedSteps: [SAMLSignInRecipe.Step] = []
    private var recordPage = 0

    // Observation (always on for interactive sign-ins): what actually happens,
    // for the SAML interaction log — pages, user actions, timing.
    private var sessionStart = Date()
    private var observedActions = 0
    private var observedPages = 0
    private var elapsed: Double { (Date().timeIntervalSince(sessionStart) * 10).rounded() / 10 }
    /// After a successful *recording*, the learned recipe and the password the
    /// user typed (for the caller to store in the Keychain). Never persisted here.
    private(set) var capturedRecipe: SAMLSignInRecipe?
    private(set) var capturedPassword: String?

    init(gateway: GatewayConfig) {
        self.gateway = gateway
    }

    /// Opens the sign-in and watches for the session cookie. `interactive`
    /// shows the window for the user to complete (and, if `record`, learns the
    /// recipe). A non-interactive attempt (autoconnect at launch/wake, a tunnel
    /// bringing its gateway up) runs the same flow with the window *hidden*:
    /// with a live IdP session the whole dance settles into the cookie in a
    /// couple of seconds with zero input — the common case, since IdP sessions
    /// long outlive VPN sessions. If the flow instead parks on a page that
    /// needs the user (expired session, fresh Duo), the deadline reports
    /// `.interactionRequired` and the gateway shows "click Connect" — a hidden
    /// window is never left waiting for input that can't arrive.
    func begin(
        interactive: Bool = true,
        record: Bool = false,
        replayPassword: String? = nil,
        replayCodeProvider: (@MainActor () async -> String?)? = nil,
        completion: @escaping (Result<String, Error>) -> Void
    ) {
        self.completion = completion
        self.recording = record
        self.isInteractive = interactive
        self.replayPassword = replayPassword
        self.replayCodeProvider = replayCodeProvider
        sessionStart = Date()

        SAMLInteractionLog.append("start", gateway: gateway.name, [
            "interactive": interactive,
            "record": record,
            "hasRecipe": gateway.signInRecipe != nil,
            "recipeSteps": gateway.signInRecipe?.steps.count ?? 0,
            "samlGroup": gateway.samlGroup ?? "",
        ])

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
        // Watch which controls the user fills/clicks — always, so every sign-in
        // feeds the interaction log (locators only). Injected into every frame
        // (Duo can be in an iframe). Only a *recording* session additionally
        // captures the password value (for the Keychain, never the recipe).
        configuration.userContentController.add(self, name: "burrowRec")
        configuration.userContentController.addUserScript(
            WKUserScript(source: Self.recorderScript(captureValues: record), injectionTime: .atDocumentEnd, forMainFrameOnly: false)
        )
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

        if interactive {
            MenuBarPopover.dismiss()
            window.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
        } else {
            // Silent attempt: the window must be *ordered in* — a WKWebView
            // outside a displayable window has rendering suspended, so
            // requestAnimationFrame never ticks and Okta's SPA login never
            // mounts its form (observed: every hidden attempt stalled on
            // page 1). So it goes on screen, but imperceptibly: fully
            // transparent, far offscreen, non-interactive, never key, no
            // activation. A live IdP session then flashes through to the
            // cookie; an expired one is driven by recipe replay (below).
            // Anything still unfinished at the deadline fails over to
            // "click Connect" instead of popping UI at an unexpected moment.
            window.alphaValue = 0
            window.ignoresMouseEvents = true
            window.collectionBehavior = [.transient, .ignoresCycle, .canJoinAllSpaces]
            window.setFrameOrigin(NSPoint(x: -20_000, y: -20_000))
            window.orderBack(nil)
            let canReplay = !(gateway.signInRecipe?.isEmpty ?? true)
            silentDeadlineTask = Task { @MainActor [weak self] in
                try? await Task.sleep(for: .seconds(canReplay ? 45 : 25))
                guard let self, self.completion != nil else { return }
                SAMLInteractionLog.append("needs-interaction", gateway: self.gateway.name)
                self.finish(.failure(ACSAMLError.interactionRequired))
            }
            if canReplay {
                startReplay()
            }
        }
    }

    // MARK: - Silent recipe replay

    /// Walks the learned steps in order, waiting for each control to appear
    /// (Okta's flow is a SPA: "Next" morphs the page in place before the
    /// password field exists). The cookie watcher ends the attempt the moment
    /// the ASA hands over the session, wherever the replay happens to be; a
    /// step whose control never shows up just lets the deadline fail over.
    private func startReplay() {
        guard replayTask == nil, let recipe = gateway.signInRecipe else { return }
        let steps = recipe.steps
        replayTask = Task { @MainActor [weak self] in
            for (index, step) in steps.enumerated() {
                guard let self, self.completion != nil else { return }
                if step.action == .fillPassword && self.replayPassword == nil {
                    SAMLInteractionLog.append("replay-no-password", gateway: self.gateway.name)
                    return
                }
                let done = await self.performReplayStep(step)
                guard self.completion != nil else { return }
                SAMLInteractionLog.append("replay-step", gateway: self.gateway.name, [
                    "i": index,
                    "a": step.action.rawValue,
                    "ok": done,
                ])
                if !done { return }
                // Give the page's own handlers a beat before the next control.
                try? await Task.sleep(for: .milliseconds(400))
            }
        }
    }

    /// Retries the step's JS until its control exists (SPA transitions take a
    /// moment) — up to ~12s — then performs it. True on success.
    private func performReplayStep(_ step: SAMLSignInRecipe.Step) async -> Bool {
        var secret: String?
        switch step.action {
        case .fillPassword:
            secret = replayPassword
        case .fillCode:
            // Generated at fill time — codes expire per TOTP period. May show
            // the system auth sheet (Touch ID) unless the unlock cache is warm.
            secret = await replayCodeProvider?()
            guard secret != nil else {
                SAMLInteractionLog.append("replay-no-code", gateway: gateway.name)
                return false
            }
        case .check, .click:
            secret = nil
        }
        let script = SAMLReplayScript.js(for: step, secret: secret)
        for _ in 0..<24 {
            guard completion != nil, let webView else { return false }
            let result = try? await webView.evaluateJavaScript(script)
            if (result as? String) == "ok" {
                return true
            }
            try? await Task.sleep(for: .milliseconds(500))
        }
        return false
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
        observedPages += 1
        SAMLInteractionLog.append("page", gateway: gateway.name, [
            "n": observedPages,
            "url": SAMLInteractionLog.describeURL(webView.url),
            "t": elapsed,
        ])
        checkForSessionCookie()
    }

    // MARK: - Recording

    /// Captured while the user signs in once: each control they touch, as a
    /// robust locator, in order. The password value is captured separately so it
    /// can go to the Keychain — it is never written into the recipe.
    func userContentController(_ controller: WKUserContentController, didReceive message: WKScriptMessage) {
        guard message.name == "burrowRec",
              let body = message.body as? [String: Any],
              let action = body["action"] as? String,
              let raw = body["field"] as? [String: Any] else {
            return
        }
        observedActions += 1
        SAMLInteractionLog.append("action", gateway: gateway.name, [
            "a": action,
            "el": SAMLInteractionLog.describeField(
                tag: raw["tag"] as? String,
                type: raw["type"] as? String,
                name: raw["name"] as? String,
                elementID: raw["id"] as? String,
                label: raw["ariaLabel"] as? String,
                text: raw["text"] as? String
            ),
            "page": observedPages,
            "t": elapsed,
        ])
        guard recording else { return }
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
        // For secret-bearing fields the recorder's `text` carries the typed
        // value — it must never reach the stored recipe. The password goes to
        // the Keychain (capturedPassword above); codes are regenerated live.
        let isSecretField = mapped == .fillPassword || mapped == .fillCode
        let field = SAMLSignInRecipe.Field(
            tag: (raw["tag"] as? String) ?? "",
            type: nonEmpty(raw["type"]),
            name: nonEmpty(raw["name"]),
            elementID: nonEmpty(raw["id"]),
            autocomplete: nonEmpty(raw["autocomplete"]),
            ariaLabel: nonEmpty(raw["ariaLabel"]),
            placeholder: nonEmpty(raw["placeholder"]),
            text: isSecretField ? nil : nonEmpty(raw["text"])
        )
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
        let outcome: String
        switch result {
        case .success: outcome = "success"
        case .failure(let error as ACSAMLError):
            switch error {
            case .cancelled: outcome = "cancelled"
            case .interactionRequired: outcome = "needs-interaction"
            case .badServer: outcome = "bad-server"
            }
        case .failure: outcome = "error"
        }
        SAMLInteractionLog.append("outcome", gateway: gateway.name, [
            "result": outcome,
            "t": elapsed,
            "pages": observedPages,
            "actions": observedActions,
            "recordedSteps": recordedSteps.count,
            "recipeCaptured": capturedRecipe != nil,
        ])
        self.completion = nil
        cookiePollTask?.cancel()
        cookiePollTask = nil
        silentDeadlineTask?.cancel()
        silentDeadlineTask = nil
        replayTask?.cancel()
        replayTask = nil
        replayPassword = nil
        replayCodeProvider = nil
        webView?.configuration.userContentController.removeScriptMessageHandler(forName: "burrowRec")
        if closeWindow {
            window?.delegate = nil
            window?.close()
        }
        window = nil
        webView?.navigationDelegate = nil
        webView = nil
        completion(result)
    }

    // Injected into every frame: reports which control the user fills, ticks,
    // or clicks (as a locator). Only a recording session includes the password
    // *value* (headed for the Keychain); observation posts locators alone.
    private static func recorderScript(captureValues: Bool) -> String {
        """
        (function(){
          if (window.__burrowRec) return; window.__burrowRec = 1;
          var CAPTURE_VALUES = \(captureValues ? "true" : "false");
          function post(m){ try { window.webkit.messageHandlers.burrowRec.postMessage(m); } catch(e){} }
          function labelText(el){ try { return (el.labels && el.labels.length) ? (el.labels[0].innerText||'') : ''; } catch(e){ return ''; } }
          function attr(el,n){ try { return el.getAttribute(n) || ''; } catch(e){ return ''; } }
          function desc(el){
            // el.value is a *label* only for button-ish inputs; for text fields
            // it is what the user typed and must never leave the page.
            var valueIsLabel = (el.type==='submit'||el.type==='button');
            return { tag:(el.tagName||'').toLowerCase(), type:(el.type||''), name:(el.name||''), id:(el.id||''),
                     autocomplete:attr(el,'autocomplete'), ariaLabel:attr(el,'aria-label'), placeholder:(el.placeholder||''),
                     text:((el.innerText || (valueIsLabel ? el.value : '') || labelText(el) || '')+'').trim().slice(0,60) };
          }
          var otpRe = /(one-time|onetime|otp|passcode|mfa|verifica|token|\\bcode\\b)/i;
          document.addEventListener('change', function(e){
            var el=e.target; if(!el||!el.tagName) return;
            if(el.tagName==='INPUT' && el.type==='checkbox' && el.checked) post({action:'check', field:desc(el)});
            if(el.tagName==='INPUT' && el.type==='password' && el.value){
              var m={action:'password', field:desc(el)};
              if(CAPTURE_VALUES) m.value=el.value;
              post(m);
            }
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
}
