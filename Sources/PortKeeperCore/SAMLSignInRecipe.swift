import Foundation

/// A learned sequence of steps to drive an IdP's (Okta/SAML) web sign-in for a
/// VPN gateway, captured by recording the user doing it once. It stores *how* to
/// find each control (robust element hints — never volatile generated IDs) and
/// *what* to do, but never any secret value: the password lives in the Keychain
/// and the 2FA code is generated live (behind Touch ID) at replay time.
public struct SAMLSignInRecipe: Codable, Sendable, Equatable {
    /// Robust locator for a form control. Replay matches on the most stable
    /// attributes first (type/name/autocomplete/label) so a minor markup change
    /// doesn't break it.
    public struct Field: Codable, Sendable, Equatable {
        public var tag: String
        public var type: String?
        public var name: String?
        public var elementID: String?
        public var autocomplete: String?
        public var ariaLabel: String?
        public var placeholder: String?
        /// Trimmed visible text (button label) or associated <label> text.
        public var text: String?

        public init(
            tag: String,
            type: String? = nil,
            name: String? = nil,
            elementID: String? = nil,
            autocomplete: String? = nil,
            ariaLabel: String? = nil,
            placeholder: String? = nil,
            text: String? = nil
        ) {
            self.tag = tag
            self.type = type
            self.name = name
            self.elementID = elementID
            self.autocomplete = autocomplete
            self.ariaLabel = ariaLabel
            self.placeholder = placeholder
            self.text = text
        }
    }

    public enum Action: String, Codable, Sendable {
        case fillPassword   // fill from Keychain
        case fillCode       // fill a live 2FA code (Touch ID each time)
        case check          // tick a checkbox (e.g. "remember this computer")
        case click          // press a button (Continue / Verify / …)
    }

    public struct Step: Codable, Sendable, Equatable {
        /// Which page of the flow this happened on (a navigation counter), so
        /// replay knows when to wait for the next page.
        public var page: Int
        public var action: Action
        public var field: Field

        public init(page: Int, action: Action, field: Field) {
            self.page = page
            self.action = action
            self.field = field
        }
    }

    public var steps: [Step]
    /// ISO-8601 timestamp of when this was recorded (informational).
    public var recordedAt: String?

    public init(steps: [Step], recordedAt: String? = nil) {
        self.steps = steps
        self.recordedAt = recordedAt
    }

    public var isEmpty: Bool { steps.isEmpty }

    /// Whether the recipe includes a 2FA step (so we know a linked authenticator
    /// account is required for replay).
    public var needsTwoFactor: Bool { steps.contains { $0.action == .fillCode } }
}

/// Generates the self-contained JavaScript that replays one recipe step in the
/// sign-in web view. Locates the control by the most stable hints first (id,
/// then name, then tag/type + visible label); fills via the native value setter
/// plus input/change events so React-controlled inputs (Okta) register the
/// change. Returns "ok" when performed, "missing" when the control isn't on
/// the page yet (the caller polls — SPA transitions take a moment).
public enum SAMLReplayScript {
    /// `secret` is whatever the step's fill action needs: the Keychain password
    /// for fillPassword, a freshly generated TOTP code for fillCode.
    public static func js(for step: SAMLSignInRecipe.Step, secret: String?) -> String {
        let field = step.field
        var locator = ""
        if let id = field.elementID {
            locator += "var e=document.getElementById(\(quote(id))); if(e) return e;\n"
        }
        if let name = field.name {
            locator += "var n=document.getElementsByName(\(quote(name))); if(n.length) return n[0];\n"
        }
        let selector = field.tag + (field.type.map { "[type=\"\($0)\"]" } ?? "")
        locator += "var c=Array.from(document.querySelectorAll(\(quote(selector)))).filter(function(x){return x.offsetParent!==null;});\n"
        if let text = field.text {
            locator += "var m=c.find(function(x){return ((x.value||x.textContent)||'').trim()===\(quote(text));}); if(m) return m;\n"
        }
        locator += "return c[0]||null;"

        let action: String
        switch step.action {
        case .fillPassword, .fillCode:
            action = """
            var setter=Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype,'value').set;
            setter.call(el, \(quote(secret ?? "")));
            el.dispatchEvent(new Event('input',{bubbles:true}));
            el.dispatchEvent(new Event('change',{bubbles:true}));
            """
        case .check:
            action = "if(!el.checked){el.click();}"
        case .click:
            action = "el.click();"
        }
        return """
        (function(){
        function find(){
        \(locator)
        }
        var el=find();
        if(!el) return "missing";
        \(action)
        return "ok";
        })()
        """
    }

    /// JSON-escapes a value into a JS string literal (quotes, backslashes,
    /// newlines, unicode — all safe to embed).
    static func quote(_ value: String) -> String {
        let data = (try? JSONSerialization.data(withJSONObject: [value]))
            .flatMap { String(data: $0, encoding: .utf8) } ?? "[\"\"]"
        return String(data.dropFirst().dropLast())
    }
}
