import Foundation
import AppSentinelCore

public enum AppLauncherError: Error, CustomStringConvertible {
    case notAnAppBundle(String)
    case missingInfoPlist(String)
    case missingExecutable(String)
    case launchFailed(String)

    public var description: String {
        switch self {
        case .notAnAppBundle(let path): return "指定路径不是有效的 .app 应用包：\(path)"
        case .missingInfoPlist(let path): return "应用包缺少 Info.plist：\(path)"
        case .missingExecutable(let path): return "应用包中找不到可执行文件：\(path)"
        case .launchFailed(let reason): return "启动目标应用失败：\(reason)"
        }
    }
}

/// Resolves a `.app` bundle to its real executable and launches it as a
/// child of AppSentinel, so the monitored process tree is rooted at a
/// process AppSentinel itself started (and can identify unambiguously).
public struct AppLauncher {
    public init() {}

    public func resolveExecutable(appBundlePath: String) throws -> String {
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: appBundlePath, isDirectory: &isDirectory), isDirectory.boolValue,
              appBundlePath.hasSuffix(".app") else {
            throw AppLauncherError.notAnAppBundle(appBundlePath)
        }

        let infoPlistPath = (appBundlePath as NSString).appendingPathComponent("Contents/Info.plist")
        guard let plistData = FileManager.default.contents(atPath: infoPlistPath),
              let plist = try? PropertyListSerialization.propertyList(from: plistData, options: [], format: nil) as? [String: Any],
              let executableName = plist["CFBundleExecutable"] as? String else {
            throw AppLauncherError.missingInfoPlist(infoPlistPath)
        }

        let executablePath = (appBundlePath as NSString).appendingPathComponent("Contents/MacOS/\(executableName)")
        guard FileManager.default.isExecutableFile(atPath: executablePath) else {
            throw AppLauncherError.missingExecutable(executablePath)
        }
        return executablePath
    }

    /// Launches the resolved executable and returns a handle holding both
    /// its pid and the owning `Process` object. The caller must keep the
    /// handle alive for the session's duration: `Process` installs a
    /// `SIGCHLD`-based reaper only once a termination handler is attached
    /// (set here to a no-op), which is what keeps the root from becoming a
    /// zombie once it exits. Liveness itself is still checked the same way
    /// as any other tracked process — via the process table — so the root
    /// is observed exactly like its descendants.
    public func launch(executablePath: String, arguments: [String] = []) throws -> LaunchedProcess {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executablePath)
        process.arguments = arguments
        process.terminationHandler = { _ in }
        do {
            try process.run()
        } catch {
            throw AppLauncherError.launchFailed(error.localizedDescription)
        }
        return LaunchedProcess(pid: ProcessID(process.processIdentifier), process: process)
    }
}

public final class LaunchedProcess {
    public let pid: ProcessID
    public let process: Process

    init(pid: ProcessID, process: Process) {
        self.pid = pid
        self.process = process
    }
}
