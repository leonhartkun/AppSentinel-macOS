import Foundation
import AppSentinelCore

/// Reads certificate metadata via the built-in `security` command-line
/// tool. Only ever reads — never adds, deletes, or changes trust for a
/// certificate. Defaults to the user's login keychain, which does not
/// require elevated privileges; the system keychain can be added by the
/// caller if AppSentinel is ever run with the privileges to read it.
public struct RealCertificateSnapshot: CertificateSnapshotting {
    public let keychainPaths: [String]

    public init(keychainPaths: [String] = [RealCertificateSnapshot.defaultLoginKeychainPath()]) {
        self.keychainPaths = keychainPaths
    }

    public static func defaultLoginKeychainPath() -> String {
        NSHomeDirectory() + "/Library/Keychains/login.keychain-db"
    }

    public func snapshot() throws -> [CertificateRecord] {
        var records: [CertificateRecord] = []
        for path in keychainPaths {
            guard FileManager.default.fileExists(atPath: path) else { continue }
            let output = try ShellRunner.run("/usr/bin/security", arguments: ["find-certificate", "-a", "-Z", path])
            records.append(contentsOf: Self.parse(output, keychainPath: path))
        }
        return records
    }

    static func parse(_ output: String, keychainPath: String) -> [CertificateRecord] {
        var records: [CertificateRecord] = []
        var currentFingerprint: String?
        var currentLabel: String?

        func flush() {
            if let fingerprint = currentFingerprint {
                records.append(CertificateRecord(
                    sha1Fingerprint: fingerprint,
                    subject: currentLabel ?? "(未知)",
                    keychainPath: keychainPath
                ))
            }
        }

        for rawLine in output.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = String(rawLine)
            if line.hasPrefix("SHA-1 hash: ") {
                flush()
                currentFingerprint = line.replacingOccurrences(of: "SHA-1 hash: ", with: "").trimmingCharacters(in: .whitespaces)
                currentLabel = nil
            } else if line.contains("\"labl\"<blob>=") {
                currentLabel = extractQuoted(line)
            }
        }
        flush()
        return records
    }

    private static func extractQuoted(_ line: String) -> String? {
        guard let firstQuote = line.firstIndex(of: "\"") else { return nil }
        let afterFirst = line.index(after: firstQuote)
        guard let secondQuote = line[afterFirst...].firstIndex(of: "\"") else { return nil }
        // The attribute name itself is quoted (e.g. "labl"), so re-scan
        // for the value's quotes after the `=`.
        guard let equalsIndex = line.firstIndex(of: "=") else { return nil }
        let afterEquals = line[line.index(after: equalsIndex)...]
        guard let openQuote = afterEquals.firstIndex(of: "\"") else { return nil }
        let afterOpen = afterEquals.index(after: openQuote)
        guard let closeQuote = afterEquals[afterOpen...].lastIndex(of: "\"") else { return nil }
        _ = secondQuote
        return String(afterEquals[afterOpen..<closeQuote])
    }
}
