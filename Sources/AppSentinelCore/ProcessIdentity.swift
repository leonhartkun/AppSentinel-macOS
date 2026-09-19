import Foundation

/// A lightweight, hashable wrapper around a POSIX process id.
public struct ProcessID: Hashable, Comparable, Sendable, Codable, CustomStringConvertible {
    public let rawValue: Int32

    public init(_ rawValue: Int32) {
        self.rawValue = rawValue
    }

    public static func < (lhs: ProcessID, rhs: ProcessID) -> Bool {
        lhs.rawValue < rhs.rawValue
    }

    public var description: String { String(rawValue) }
}

/// A point-in-time observation of one process, as reported by the process
/// listing adapter (real `ps`-backed on macOS, synthetic in tests).
public struct ProcessSnapshot: Sendable, Equatable {
    public let pid: ProcessID
    public let parentPID: ProcessID
    public let executablePath: String?

    public init(pid: ProcessID, parentPID: ProcessID, executablePath: String?) {
        self.pid = pid
        self.parentPID = parentPID
        self.executablePath = executablePath
    }
}

/// One entry in a process ancestry chain, from the offending process up to
/// (and including) the monitored root. Used only for evidence — it never
/// carries file contents or credential material.
public struct AncestryEntry: Sendable, Equatable, Codable {
    public let pid: ProcessID
    public let executablePath: String?
    public let sha256: String?

    public init(pid: ProcessID, executablePath: String?, sha256: String?) {
        self.pid = pid
        self.executablePath = executablePath
        self.sha256 = sha256
    }
}
