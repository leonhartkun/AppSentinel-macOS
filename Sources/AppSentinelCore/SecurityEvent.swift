import Foundation

/// A certificate observed in a keychain snapshot. Only metadata is ever
/// kept — never key material.
public struct CertificateRecord: Sendable, Equatable, Codable, Hashable {
    public let sha1Fingerprint: String
    public let subject: String
    public let keychainPath: String

    public init(sha1Fingerprint: String, subject: String, keychainPath: String) {
        self.sha1Fingerprint = sha1Fingerprint
        self.subject = subject
        self.keychainPath = keychainPath
    }
}

/// A snapshot of the network configuration AppSentinel cares about.
public struct NetworkState: Sendable, Equatable, Codable {
    public var httpProxy: String?
    public var httpsProxy: String?
    public var dnsServers: [String]
    public var defaultRouteGateway: String?

    public init(httpProxy: String? = nil, httpsProxy: String? = nil, dnsServers: [String] = [], defaultRouteGateway: String? = nil) {
        self.httpProxy = httpProxy
        self.httpsProxy = httpsProxy
        self.dnsServers = dnsServers
        self.defaultRouteGateway = defaultRouteGateway
    }
}

/// A normalized description of what a filesystem path is sensitive for.
public enum SensitivePathCategory: String, Sendable, Codable {
    case sshPrivateKey
    case browserCredentialStore
    case keychainFile
    case launchPersistence
    case loginItem
    case systemExtension
    case other
}

/// The kinds of security-relevant activity AppSentinel normalizes both
/// `eslogger` and polling observations into before policy evaluation.
public enum SecurityEventKind: Sendable, Equatable {
    case processExec(path: String, arguments: [String], sha256: String?)
    case processFork(childPID: ProcessID)
    case processExit
    case sensitivePathRead(path: String, category: SensitivePathCategory)
    case sensitivePathWrite(path: String, category: SensitivePathCategory)
    case executableDropped(path: String, sha256: String?)
    case certificateAdded(CertificateRecord)
    case certificateRemoved(CertificateRecord)
    case certificateTrustChanged(CertificateRecord)
    case networkStateChanged(before: NetworkState, after: NetworkState)
}

/// One normalized event, attributed to a process in the monitored tree.
public struct SecurityEvent: Sendable, Equatable {
    public let pid: ProcessID
    public let timestamp: Date
    public let kind: SecurityEventKind

    public init(pid: ProcessID, timestamp: Date, kind: SecurityEventKind) {
        self.pid = pid
        self.timestamp = timestamp
        self.kind = kind
    }
}
