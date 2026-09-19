import Foundation

/// Determines whether `/usr/sbin/eslogger` (macOS's built-in Endpoint
/// Security event logger) can actually be used this session. Without the
/// Endpoint Security entitlement, AppSentinel cannot query authorization
/// directly — instead it launches `eslogger` briefly and checks whether it
/// starts successfully or fails immediately with a privilege error, which
/// is the same signal a human running it from Terminal would see.
public enum ESLoggerAvailabilityProbe {
    public static let binaryPath = "/usr/sbin/eslogger"

    /// How long to wait for `eslogger` to either fail fast or prove it
    /// started successfully (it never prints anything on success — it
    /// just blocks emitting NDJSON — so "still running after the
    /// deadline" is treated as success).
    public static func probe(timeout: TimeInterval = 0.6) -> ESLoggerAvailability {
        guard FileManager.default.isExecutableFile(atPath: binaryPath) else {
            return ESLoggerAvailability(isAvailable: false, reason: "系统未找到 eslogger 工具")
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: binaryPath)
        process.arguments = ["exit"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe

        do {
            try process.run()
        } catch {
            return ESLoggerAvailability(isAvailable: false, reason: "无法启动 eslogger：\(error.localizedDescription)")
        }

        let deadline = Date().addingTimeInterval(timeout)
        while process.isRunning, Date() < deadline {
            Thread.sleep(forTimeInterval: 0.05)
        }

        if process.isRunning {
            process.terminate()
            process.waitUntilExit()
            return ESLoggerAvailability(isAvailable: true, reason: nil)
        }

        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        if output.contains("Not privileged") || output.contains("ES_NEW_CLIENT_RESULT_ERR") {
            return ESLoggerAvailability(isAvailable: false, reason: "eslogger 权限不足，需要以 root 身份运行并授予完全磁盘访问权限")
        }
        return ESLoggerAvailability(isAvailable: false, reason: "eslogger 提前退出：\(output.trimmingCharacters(in: .whitespacesAndNewlines))")
    }
}
