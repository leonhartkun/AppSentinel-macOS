import Foundation

/// A path-keyed snapshot of file modification times, used to detect
/// creation/modification/removal of files under a watched directory
/// (LaunchAgents, LaunchDaemons, login items, system extensions) between
/// two polling passes. Pure data — the polling adapter is responsible for
/// producing it from the real filesystem.
public struct DirectorySnapshot: Sendable, Equatable {
    public let modificationTimeByPath: [String: Date]

    public init(modificationTimeByPath: [String: Date]) {
        self.modificationTimeByPath = modificationTimeByPath
    }

    public static let empty = DirectorySnapshot(modificationTimeByPath: [:])
}

public enum PathChangeKind: Sendable, Equatable {
    case created
    case modified
    case removed
}

public struct PathChange: Sendable, Equatable {
    public let path: String
    public let kind: PathChangeKind
}

public enum StateSnapshotDiff {
    /// Compute created/modified/removed paths between two directory
    /// snapshots. Order is not significant to callers.
    public static func diff(before: DirectorySnapshot, after: DirectorySnapshot) -> [PathChange] {
        var changes: [PathChange] = []
        for (path, afterTime) in after.modificationTimeByPath {
            if let beforeTime = before.modificationTimeByPath[path] {
                if beforeTime != afterTime {
                    changes.append(PathChange(path: path, kind: .modified))
                }
            } else {
                changes.append(PathChange(path: path, kind: .created))
            }
        }
        for path in before.modificationTimeByPath.keys where after.modificationTimeByPath[path] == nil {
            changes.append(PathChange(path: path, kind: .removed))
        }
        return changes
    }

    /// Compute added/removed certificates between two snapshots (keyed by
    /// SHA-1 fingerprint, since that is stable across metadata changes).
    public static func diffCertificates(
        before: [CertificateRecord],
        after: [CertificateRecord]
    ) -> (added: [CertificateRecord], removed: [CertificateRecord]) {
        let beforeByFingerprint = Dictionary(uniqueKeysWithValues: before.map { ($0.sha1Fingerprint, $0) })
        let afterByFingerprint = Dictionary(uniqueKeysWithValues: after.map { ($0.sha1Fingerprint, $0) })

        let added = Set(afterByFingerprint.keys).subtracting(beforeByFingerprint.keys).compactMap { afterByFingerprint[$0] }
        let removed = Set(beforeByFingerprint.keys).subtracting(afterByFingerprint.keys).compactMap { beforeByFingerprint[$0] }
        return (added, removed)
    }
}
