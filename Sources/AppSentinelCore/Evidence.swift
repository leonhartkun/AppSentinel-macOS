import Foundation

/// One line of the session's plain-text event log. Only paths, hashes and
/// descriptive strings are ever included — never file contents, never
/// credential values.
public struct EvidenceEvent: Codable, Equatable {
    public let timestamp: Date
    public let pid: Int32
    public let description: String
    public let decision: String

    public init(timestamp: Date, pid: Int32, description: String, decision: String) {
        self.timestamp = timestamp
        self.pid = pid
        self.description = description
        self.decision = decision
    }
}

/// The full evidence record written when a session ends with a critical
/// violation: the triggering event, the offending process's ancestry chain
/// (with executable hashes, not contents), and any before/after state diff
/// that is relevant.
public struct ViolationEvidence: Codable, Equatable {
    public let sessionID: String
    public let timestamp: Date
    public let triggeringReason: String
    public let ancestry: [AncestryEntry]
    public let stateDiffLines: [String]

    public init(sessionID: String, timestamp: Date, triggeringReason: String, ancestry: [AncestryEntry], stateDiffLines: [String]) {
        self.sessionID = sessionID
        self.timestamp = timestamp
        self.triggeringReason = triggeringReason
        self.ancestry = ancestry
        self.stateDiffLines = stateDiffLines
    }
}

/// Writes evidence to a local session directory. Pure with respect to
/// content — the only I/O is encoding JSON/text to the filesystem, so tests
/// can point it at a temporary directory and inspect the resulting files
/// directly instead of mocking a protocol.
public struct EvidenceLogger {
    public let sessionDirectory: URL

    public init(sessionDirectory: URL) throws {
        self.sessionDirectory = sessionDirectory
        try FileManager.default.createDirectory(at: sessionDirectory, withIntermediateDirectories: true)
    }

    private static func makeEncoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }

    /// NDJSON requires exactly one compact JSON object per line; the
    /// pretty-printed encoder above would spread a single event across
    /// several lines and break that invariant.
    private static func makeCompactEncoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }

    public func appendEvent(_ event: EvidenceEvent) throws {
        let line = try String(data: Self.makeCompactEncoder().encode(event), encoding: .utf8)! + "\n"
        let url = sessionDirectory.appendingPathComponent("events.ndjson")
        try Self.append(line, to: url)
    }

    public func writeViolation(_ violation: ViolationEvidence) throws {
        let url = sessionDirectory.appendingPathComponent("violation.json")
        let data = try Self.makeEncoder().encode(violation)
        try data.write(to: url, options: .atomic)
    }

    public func writeSessionSummary(_ summary: [String: String]) throws {
        let url = sessionDirectory.appendingPathComponent("session.json")
        let data = try JSONSerialization.data(withJSONObject: summary, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
        try data.write(to: url, options: .atomic)
    }

    private static func append(_ string: String, to url: URL) throws {
        if FileManager.default.fileExists(atPath: url.path) {
            let handle = try FileHandle(forWritingTo: url)
            defer { try? handle.close() }
            handle.seekToEndOfFile()
            handle.write(string.data(using: .utf8)!)
        } else {
            try string.write(to: url, atomically: true, encoding: .utf8)
        }
    }
}
