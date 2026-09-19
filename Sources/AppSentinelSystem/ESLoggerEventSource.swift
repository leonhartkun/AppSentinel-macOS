import Foundation
import AppSentinelCore

/// Runs the real `eslogger` binary for the lifetime of a session and
/// converts its NDJSON stream into `SecurityEvent`s. Only started when
/// `ESLoggerAvailabilityProbe` reports success. Requires root and Full
/// Disk Access in practice; on a normal, non-elevated run AppSentinel
/// falls back to `PollingEventSource` instead of using this adapter.
///
/// `eslogger`'s exact JSON field layout has shifted across macOS releases,
/// so field extraction goes through `JSONPath`'s defensive lookups; a line
/// this adapter cannot confidently interpret is skipped rather than
/// guessed at, since a missed detection here is still caught by the
/// polling adapter running alongside it.
public final class ESLoggerEventSource: SecurityEventSource {
    public static let subscribedEventTypes = ["exec", "fork", "exit", "create", "rename", "unlink"]

    private let sensitiveClassifier: SensitivePathClassifier
    private var process: Process?
    private var stdoutHandle: FileHandle?
    private var buffer = Data()

    public init(sensitiveClassifier: SensitivePathClassifier) {
        self.sensitiveClassifier = sensitiveClassifier
    }

    public func start(onEvent: @escaping (SecurityEvent) -> Void) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: ESLoggerAvailabilityProbe.binaryPath)
        process.arguments = Self.subscribedEventTypes
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice

        pipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty else { return }
            self?.consume(data, onEvent: onEvent)
        }

        try process.run()
        self.process = process
        self.stdoutHandle = pipe.fileHandleForReading
    }

    public func stop() {
        stdoutHandle?.readabilityHandler = nil
        if let process, process.isRunning {
            process.terminate()
        }
        process = nil
        stdoutHandle = nil
    }

    private func consume(_ data: Data, onEvent: @escaping (SecurityEvent) -> Void) {
        buffer.append(data)
        while let newlineRange = buffer.range(of: Data([0x0A])) {
            let lineData = buffer.subdata(in: buffer.startIndex..<newlineRange.lowerBound)
            buffer.removeSubrange(buffer.startIndex..<newlineRange.upperBound)
            guard !lineData.isEmpty,
                  let event = Self.parseLine(lineData, classifier: sensitiveClassifier) else { continue }
            onEvent(event)
        }
    }

    static func parseLine(_ data: Data, classifier: SensitivePathClassifier) -> SecurityEvent? {
        guard let json = try? JSONSerialization.jsonObject(with: data) else { return nil }

        guard let subjectPID = JSONPath.pid(ofProcessAt: ["process"], in: json) else { return nil }
        let timestamp = Date()

        if let target = JSONPath.value(json, ["event", "exec", "target"]) {
            let execPID = JSONPath.pid(ofProcessAt: [], in: target) ?? subjectPID
            let path = JSONPath.executablePath(ofProcessAt: [], in: target) ?? ""
            let args = (JSONPath.value(target, ["args"]) as? [String]) ?? []
            return SecurityEvent(pid: ProcessID(execPID), timestamp: timestamp, kind: .processExec(path: path, arguments: args, sha256: nil))
        }

        if let child = JSONPath.value(json, ["event", "fork", "child"]) {
            guard let childPID = JSONPath.pid(ofProcessAt: [], in: child) else { return nil }
            return SecurityEvent(pid: ProcessID(subjectPID), timestamp: timestamp, kind: .processFork(childPID: ProcessID(childPID)))
        }

        if JSONPath.value(json, ["event", "exit"]) != nil {
            return SecurityEvent(pid: ProcessID(subjectPID), timestamp: timestamp, kind: .processExit)
        }

        if let destination = JSONPath.value(json, ["event", "create", "destination"]) {
            guard let path = createdPath(from: destination) else { return nil }
            return makePathEvent(pid: subjectPID, path: path, timestamp: timestamp, classifier: classifier, isWrite: true)
        }

        if let newPath = JSONPath.value(json, ["event", "rename", "destination", "new_path"]) {
            guard let dir = JSONPath.string(newPath, ["dir", "path"]),
                  let filename = JSONPath.string(newPath, ["filename"]) else { return nil }
            let path = dir.hasSuffix("/") ? dir + filename : dir + "/" + filename
            return makePathEvent(pid: subjectPID, path: path, timestamp: timestamp, classifier: classifier, isWrite: true)
        }

        if let target = JSONPath.value(json, ["event", "unlink", "target"]) {
            guard let path = JSONPath.string(target, ["path"]) else { return nil }
            return makePathEvent(pid: subjectPID, path: path, timestamp: timestamp, classifier: classifier, isWrite: true)
        }

        return nil
    }

    private static func createdPath(from destination: Any) -> String? {
        if let existing = JSONPath.string(destination, ["existing_file", "path"]) {
            return existing
        }
        if let dir = JSONPath.string(destination, ["new_path", "dir", "path"]),
           let filename = JSONPath.string(destination, ["new_path", "filename"]) {
            return dir.hasSuffix("/") ? dir + filename : dir + "/" + filename
        }
        return nil
    }

    private static func makePathEvent(
        pid: Int32,
        path: String,
        timestamp: Date,
        classifier: SensitivePathClassifier,
        isWrite: Bool
    ) -> SecurityEvent? {
        guard let category = classifier.classify(path) else {
            return SecurityEvent(pid: ProcessID(pid), timestamp: timestamp, kind: .executableDropped(path: path, sha256: nil)).nilIfNotDropCandidate(path: path)
        }
        let kind: SecurityEventKind = isWrite ? .sensitivePathWrite(path: path, category: category) : .sensitivePathRead(path: path, category: category)
        return SecurityEvent(pid: ProcessID(pid), timestamp: timestamp, kind: kind)
    }
}

private extension SecurityEvent {
    /// `create`/`rename` events outside any protected directory are only
    /// interesting if they land somewhere a dropped-and-executed payload
    /// would plausibly go (world-writable temp locations); everything
    /// else is normal application behavior and must not be logged.
    func nilIfNotDropCandidate(path: String) -> SecurityEvent? {
        let dropCandidateDirs = ["/tmp/", "/var/tmp/", "/private/tmp/", NSTemporaryDirectory()]
        guard dropCandidateDirs.contains(where: { path.hasPrefix($0) }) else { return nil }
        return self
    }
}
