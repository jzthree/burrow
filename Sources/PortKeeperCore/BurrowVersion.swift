import Foundation

/// The single source of truth for Burrow's release version.
/// Tag releases `v<current>`; make-dmg.sh stamps its argument into the app
/// bundle, and the install scripts stamp `git describe` so local builds are
/// distinguishable too.
public enum BurrowVersion {
    /// Fallback for contexts without a bundle Info.plist (the CLI, `swift run`).
    public static let current = "1.0.0"

    /// What to show a person: the bundle's stamped version when running as
    /// the app, otherwise the compiled-in constant.
    public static func display(bundle: Bundle = .main) -> String {
        if let stamped = bundle.infoDictionary?["CFBundleShortVersionString"] as? String,
           !stamped.isEmpty {
            return stamped
        }
        return current
    }

    /// Orders two version strings by numeric components ("1.10.0" > "1.9.1").
    /// Non-numeric versions (git hashes from source builds) are never
    /// considered newer than anything.
    public static func isNewer(_ candidate: String, than baseline: String) -> Bool {
        func components(_ version: String) -> [Int]? {
            let trimmed = version.hasPrefix("v") ? String(version.dropFirst()) : version
            let parts = trimmed.split(separator: ".").map { Int($0) }
            guard !parts.isEmpty, parts.allSatisfy({ $0 != nil }) else { return nil }
            return parts.compactMap { $0 }
        }
        guard let new = components(candidate), let old = components(baseline) else {
            return false
        }
        for index in 0..<max(new.count, old.count) {
            let a = index < new.count ? new[index] : 0
            let b = index < old.count ? old[index] : 0
            if a != b { return a > b }
        }
        return false
    }
}
