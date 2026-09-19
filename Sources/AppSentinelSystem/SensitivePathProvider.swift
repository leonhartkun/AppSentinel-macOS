import Foundation
import AppSentinelCore

/// Default sensitive locations on the real system: the user's SSH
/// directory, browser credential stores, the login keychain, and the
/// directories used for launch-persistence, login items, and system
/// extensions. Read-only — AppSentinel only watches these, never writes to
/// them itself.
public struct RealSensitivePathProvider: SensitivePathProviding {
    public let homeDirectory: String

    public init(homeDirectory: String = NSHomeDirectory()) {
        self.homeDirectory = homeDirectory
    }

    public var watchedDirectories: [String] {
        [
            "\(homeDirectory)/.ssh",
            "\(homeDirectory)/Library/Application Support/Google/Chrome",
            "\(homeDirectory)/Library/Application Support/BraveSoftware",
            "\(homeDirectory)/Library/Application Support/Microsoft Edge",
            "\(homeDirectory)/Library/Application Support/Firefox",
            "\(homeDirectory)/Library/LaunchAgents",
            "/Library/LaunchAgents",
            "/Library/LaunchDaemons"
        ]
    }
}
