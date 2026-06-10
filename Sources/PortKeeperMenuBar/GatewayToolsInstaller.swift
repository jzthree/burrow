import AppKit
import PortKeeperCore

/// Install-on-demand for the optional VPN dependencies. Keeping them in
/// Homebrew (instead of bundling) leaves security updates for openconnect
/// and GnuTLS on Homebrew's shoulders; Burrow just makes the install a
/// one-click affair.
@MainActor
enum GatewayToolsInstaller {
    static var missingTools: [String] {
        var missing: [String] = []
        if GatewayCommandBuilder.openconnectPath() == nil {
            missing.append("openconnect")
        }
        if GatewayCommandBuilder.ocproxyPath() == nil {
            missing.append("ocproxy")
        }
        return missing
    }

    static func brewPath() -> String? {
        ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"].first {
            FileManager.default.isExecutableFile(atPath: $0)
        }
    }

    /// Prompts and, if confirmed, opens a Terminal window running the brew
    /// install. Returns true when an install was started and the caller
    /// should poll `missingTools` until it empties.
    static func promptAndInstall(missing: [String]) -> Bool {
        let toolList = missing.joined(separator: " and ")
        let alert = NSAlert()

        guard let brew = brewPath() else {
            alert.messageText = "Homebrew is required for VPN gateways"
            alert.informativeText = "VPN gateways use \(toolList) (open-source), installed via Homebrew — which isn't on this Mac yet.\n\nInstall Homebrew from brew.sh first, then connect the gateway again and Burrow will offer to install the rest."
            alert.addButton(withTitle: "Open brew.sh")
            alert.addButton(withTitle: "Cancel")
            if alert.runModal() == .alertFirstButtonReturn, let url = URL(string: "https://brew.sh") {
                NSWorkspace.shared.open(url)
            }
            return false
        }

        alert.messageText = "Install VPN tools?"
        alert.informativeText = "VPN gateways use \(toolList) (open-source). Burrow will run the install in a Terminal window so you can watch it, and connect the gateway automatically once it finishes.\n\nCommand: brew install openconnect ocproxy"
        alert.addButton(withTitle: "Install in Terminal")
        alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else {
            return false
        }

        do {
            try openInstallTerminal(brewPath: brew)
            return true
        } catch {
            // Last resort: hand the user the command.
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString("brew install openconnect ocproxy", forType: .string)
            let fallback = NSAlert()
            fallback.messageText = "Couldn't open Terminal automatically"
            fallback.informativeText = "The install command was copied to the clipboard — paste it into a terminal. Burrow will still connect automatically once the tools appear."
            fallback.addButton(withTitle: "OK")
            fallback.runModal()
            return true
        }
    }

    /// A self-deleting .command file opened in Terminal shows live progress
    /// without needing Apple Events automation permission.
    private static func openInstallTerminal(brewPath: String) throws {
        let scriptURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("burrow-install-vpn-tools.command")
        let script = """
        #!/bin/zsh
        echo "Burrow: installing VPN gateway tools (openconnect + ocproxy)..."
        echo
        "\(brewPath)" install openconnect ocproxy
        STATUS=$?
        echo
        if [ $STATUS -eq 0 ]; then
          echo "Done. Burrow will connect the gateway automatically — you can close this window."
        else
          echo "Install failed (exit $STATUS). Fix the error above and run: brew install openconnect ocproxy"
        fi
        rm -f "$0"
        exit $STATUS
        """
        try script.write(to: scriptURL, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: scriptURL.path)
        NSWorkspace.shared.open(scriptURL)
    }
}
