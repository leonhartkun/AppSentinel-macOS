import Foundation

/// AppSentinel deliberately hand-rolls argument parsing instead of taking
/// on a third-party dependency (e.g. swift-argument-parser); the surface
/// is small enough that this stays simple.
struct RunOptions {
    var appBundlePath: String
    var policyFilePath: String?
    var certificateEnrollmentDuration: TimeInterval?
    var allowedShellExecutables: [String] = []
    var allowedScriptPaths: [String] = []
    var allowedNetworkChangeFields: [String] = []
    var protectedPathExceptions: [String] = []
    var logDirectory: String?
    var forcePolling: Bool = false
}

enum ArgumentParsingError: Error, CustomStringConvertible {
    case missingSubcommand
    case unknownSubcommand(String)
    case missingAppPath
    case missingValue(String)
    case invalidDuration(String)

    var description: String {
        switch self {
        case .missingSubcommand:
            return "缺少子命令，请使用：appsentinel run <应用路径>"
        case .unknownSubcommand(let name):
            return "未知子命令：\(name)（目前仅支持 run）"
        case .missingAppPath:
            return "缺少目标应用路径，例如：appsentinel run /Applications/Example.app"
        case .missingValue(let flag):
            return "参数 \(flag) 缺少取值"
        case .invalidDuration(let raw):
            return "无法解析时长：\(raw)（示例：5m、30s、1h）"
        }
    }
}

enum ArgumentParser {
    static func parseDuration(_ raw: String) -> TimeInterval? {
        guard let unit = raw.last, let value = Double(raw.dropLast()) else { return nil }
        switch unit {
        case "s": return value
        case "m": return value * 60
        case "h": return value * 3600
        default: return nil
        }
    }

    static func parseRun(_ arguments: [String]) throws -> RunOptions {
        var remaining = arguments[...]
        guard let appPath = remaining.first, !appPath.hasPrefix("--") else {
            throw ArgumentParsingError.missingAppPath
        }
        remaining.removeFirst()

        var options = RunOptions(appBundlePath: appPath)

        func nextValue(for flag: String) throws -> String {
            guard let value = remaining.first else { throw ArgumentParsingError.missingValue(flag) }
            remaining.removeFirst()
            return value
        }

        while let flag = remaining.first {
            remaining.removeFirst()
            switch flag {
            case "--policy":
                options.policyFilePath = try nextValue(for: flag)
            case "--certificate-enrollment":
                let raw = try nextValue(for: flag)
                guard let duration = parseDuration(raw) else { throw ArgumentParsingError.invalidDuration(raw) }
                options.certificateEnrollmentDuration = duration
            case "--allow-shell":
                options.allowedShellExecutables.append(try nextValue(for: flag))
            case "--allow-script":
                options.allowedScriptPaths.append(try nextValue(for: flag))
            case "--allow-path":
                options.protectedPathExceptions.append(try nextValue(for: flag))
            case "--log-dir":
                options.logDirectory = try nextValue(for: flag)
            case "--no-eslogger":
                options.forcePolling = true
            default:
                // Unknown flags are reported by the caller via help text
                // rather than silently ignored, to avoid a mistyped flag
                // silently running with a weaker policy than intended.
                throw ArgumentParsingError.missingValue("未知参数 \(flag)")
            }
        }

        return options
    }
}
