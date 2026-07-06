import Foundation

/// The single shell-quoting implementation for every place Burrow renders a
/// command line for a shell — supervised ssh commands, openconnect commands,
/// and the Terminal launch scripts. Quoting is security-sensitive; keep it in
/// one place so a fix applies everywhere.
public enum ShellQuoting {
    public static func quote(_ argument: String) -> String {
        guard !argument.isEmpty else {
            return "''"
        }

        let safeCharacters = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_+-./:=,@%")
        if argument.unicodeScalars.allSatisfy({ safeCharacters.contains($0) }) {
            return argument
        }

        return "'\(argument.replacingOccurrences(of: "'", with: "'\\''"))'"
    }
}
