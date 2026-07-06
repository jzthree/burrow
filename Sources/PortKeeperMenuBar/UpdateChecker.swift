import Foundation

/// Asks GitHub for the newest published release. Called only from the
/// explicit "Check for Updates…" menu action — Burrow never phones home in
/// the background.
enum UpdateChecker {
    struct Release: Decodable {
        let tagName: String
        let htmlURL: String

        enum CodingKeys: String, CodingKey {
            case tagName = "tag_name"
            case htmlURL = "html_url"
        }
    }

    static func latestRelease() async throws -> Release {
        var request = URLRequest(url: URL(string: "https://api.github.com/repos/jzthree/burrow/releases/latest")!)
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        request.timeoutInterval = 15
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw UpdateCheckError.unavailable
        }
        return try JSONDecoder().decode(Release.self, from: data)
    }
}

enum UpdateCheckError: LocalizedError {
    case unavailable

    var errorDescription: String? {
        "no published releases found (or GitHub is unreachable)"
    }
}
