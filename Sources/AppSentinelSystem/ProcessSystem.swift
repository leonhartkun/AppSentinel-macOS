import Foundation
import AppSentinelCore

/// Lists processes via `/bin/ps`, macOS's built-in process inspection
/// tool. No third-party dependency, no elevated privileges required.
public struct RealProcessLister: ProcessListing {
    public init() {}

    public func currentProcesses() throws -> [ProcessSnapshot] {
        let output = try ShellRunner.run("/bin/ps", arguments: ["-Ao", "pid=,ppid=,comm="])
        var result: [ProcessSnapshot] = []
        for rawLine in output.split(separator: "\n") {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            guard !line.isEmpty else { continue }
            let fields = line.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
            guard fields.count >= 3,
                  let pid = Int32(fields[0]),
                  let ppid = Int32(fields[1]) else { continue }
            let comm = String(fields[2])
            result.append(ProcessSnapshot(pid: ProcessID(pid), parentPID: ProcessID(ppid), executablePath: comm))
        }
        return result
    }
}

/// Sends real POSIX signals via `kill(2)`.
public struct RealProcessTerminator: ProcessTerminating {
    public init() {}

    public func terminate(_ pid: ProcessID, signal: Int32) throws {
        if kill(pid.rawValue, signal) != 0 {
            let err = errno
            // ESRCH just means the process is already gone — not an error
            // AppSentinel needs to surface.
            if err != ESRCH {
                throw POSIXError(POSIXErrorCode(rawValue: err) ?? .EPERM)
            }
        }
    }

    public func isAlive(_ pid: ProcessID) -> Bool {
        kill(pid.rawValue, 0) == 0
    }
}

/// Shells out to a helper binary and captures combined stdout, throwing on
/// a non-zero exit. Centralizes `Process` boilerplate used across the
/// system adapters.
public enum ShellRunner {
    public struct Failure: Error, CustomStringConvertible {
        public let executable: String
        public let arguments: [String]
        public let exitCode: Int32
        public let output: String
        public var description: String {
            "\(executable) \(arguments.joined(separator: " ")) exited with \(exitCode): \(output)"
        }
    }

    @discardableResult
    public static func run(_ executable: String, arguments: [String]) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        try process.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        let output = String(data: data, encoding: .utf8) ?? ""
        guard process.terminationStatus == 0 else {
            throw Failure(executable: executable, arguments: arguments, exitCode: process.terminationStatus, output: output)
        }
        return output
    }
}
