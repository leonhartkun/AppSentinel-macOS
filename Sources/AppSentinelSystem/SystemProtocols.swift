import Foundation
import AppSentinelCore

/// Lists every process currently running on the system. The real
/// implementation shells out to `/bin/ps`; tests supply a synthetic list so
/// policy and tree-tracking logic never has to touch the real process
/// table.
public protocol ProcessListing: Sendable {
    func currentProcesses() throws -> [ProcessSnapshot]
}

/// Sends a termination signal to one process.
public protocol ProcessTerminating: Sendable {
    func terminate(_ pid: ProcessID, signal: Int32) throws
    func isAlive(_ pid: ProcessID) -> Bool
}

/// Computes a SHA-256 digest of an executable on disk, for evidence only —
/// never for logging file contents.
public protocol ExecutableHashing: Sendable {
    func sha256(ofFileAt path: String) -> String?
}

/// Reads certificate metadata out of a keychain.
public protocol CertificateSnapshotting: Sendable {
    func snapshot() throws -> [CertificateRecord]
}

/// Reads and (for the proxy fields only) restores network configuration.
public protocol NetworkStateSnapshotting: Sendable {
    func snapshot() throws -> NetworkState
    /// Best-effort restoration of the proxy fields captured at launch.
    /// DNS/route are reported but never silently rewritten, since
    /// AppSentinel cannot safely know which interface/service to target
    /// without risking an unrelated change.
    func restoreProxy(from state: NetworkState) throws
}

/// Supplies the set of filesystem locations AppSentinel treats as
/// sensitive by default, plus the directories it polls for
/// launch-persistence changes.
public protocol SensitivePathProviding: Sendable {
    var homeDirectory: String { get }
    var watchedDirectories: [String] { get }
}

/// Whether `eslogger` can be used this session, and why not if it can't.
public struct ESLoggerAvailability: Sendable, Equatable {
    public let isAvailable: Bool
    public let reason: String?

    public init(isAvailable: Bool, reason: String?) {
        self.isAvailable = isAvailable
        self.reason = reason
    }
}

/// A live source of security events, delivered asynchronously via a
/// callback until `stop()` is called. Implemented by both the `eslogger`
/// adapter and the polling adapter so the session driver can treat them
/// uniformly.
public protocol SecurityEventSource: AnyObject {
    func start(onEvent: @escaping (SecurityEvent) -> Void) throws
    func stop()
}
