import Foundation

/// Pure classification of filesystem paths into sensitivity categories.
/// Takes the home directory as a parameter (rather than reading
/// `NSHomeDirectory()` itself) so tests can point it at a throwaway
/// directory and never need to touch a real user's files.
public struct SensitivePathClassifier: Sendable {
    public let homeDirectory: String

    public init(homeDirectory: String) {
        self.homeDirectory = homeDirectory
    }

    public func classify(_ path: String) -> SensitivePathCategory? {
        let normalized = (path as NSString).standardizingPath

        if normalized.hasPrefix("\(homeDirectory)/.ssh/") || normalized == "\(homeDirectory)/.ssh" {
            return .sshPrivateKey
        }

        let browserCredentialSuffixes = [
            "/Login Data",
            "/Login Data-journal",
            "/logins.json",
            "/key4.db",
            "/cookies.sqlite"
        ]
        for suffix in browserCredentialSuffixes where normalized.hasSuffix(suffix) {
            return .browserCredentialStore
        }
        let browserCredentialDirs = [
            "\(homeDirectory)/Library/Application Support/Google/Chrome",
            "\(homeDirectory)/Library/Application Support/BraveSoftware",
            "\(homeDirectory)/Library/Application Support/Microsoft Edge",
            "\(homeDirectory)/Library/Application Support/Firefox"
        ]
        for dir in browserCredentialDirs where normalized.hasPrefix(dir + "/") {
            return .browserCredentialStore
        }

        if normalized.hasPrefix("\(homeDirectory)/Library/Keychains/") {
            return .keychainFile
        }

        let launchPersistenceDirs = [
            "\(homeDirectory)/Library/LaunchAgents",
            "/Library/LaunchAgents",
            "/Library/LaunchDaemons",
            "/System/Library/LaunchDaemons"
        ]
        for dir in launchPersistenceDirs where normalized == dir || normalized.hasPrefix(dir + "/") {
            return .launchPersistence
        }

        if normalized.hasSuffix("com.apple.loginitems.plist")
            || normalized.contains("/com.apple.backgroundtaskmanagementagent/") {
            return .loginItem
        }

        if normalized.contains("/com.apple.system_extensions/") {
            return .systemExtension
        }

        return nil
    }
}
