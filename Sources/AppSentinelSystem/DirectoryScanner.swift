import Foundation
import AppSentinelCore

/// Builds a `DirectorySnapshot` (path -> modification time) by walking a
/// bounded set of directories. Used by the polling adapter to detect
/// launch-persistence, login-item, and sensitive-file changes between
/// passes without needing `eslogger`.
public struct DirectoryScanner: Sendable {
    public let maxDepth: Int

    public init(maxDepth: Int = 4) {
        self.maxDepth = maxDepth
    }

    public func scan(directories: [String]) -> DirectorySnapshot {
        var result: [String: Date] = [:]
        let fileManager = FileManager.default
        for root in directories {
            scan(path: root, depth: 0, fileManager: fileManager, into: &result)
        }
        return DirectorySnapshot(modificationTimeByPath: result)
    }

    private func scan(path: String, depth: Int, fileManager: FileManager, into result: inout [String: Date]) {
        guard depth <= maxDepth else { return }
        var isDirectory: ObjCBool = false
        guard fileManager.fileExists(atPath: path, isDirectory: &isDirectory) else { return }

        guard let attributes = try? fileManager.attributesOfItem(atPath: path) else { return }
        if let type = attributes[.type] as? FileAttributeType, type == .typeSymbolicLink {
            return
        }

        if isDirectory.boolValue {
            guard let entries = try? fileManager.contentsOfDirectory(atPath: path) else { return }
            for entry in entries {
                scan(path: (path as NSString).appendingPathComponent(entry), depth: depth + 1, fileManager: fileManager, into: &result)
            }
        } else {
            if let mtime = attributes[.modificationDate] as? Date {
                result[path] = mtime
            }
        }
    }
}
