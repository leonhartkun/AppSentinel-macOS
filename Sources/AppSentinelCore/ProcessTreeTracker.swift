import Foundation

/// Tracks membership of the monitored process tree: the root process the
/// user asked AppSentinel to launch, plus every descendant it ever spawns,
/// however deeply nested. Everything not in this tree is ignored — events
/// about unrelated system processes are never attributed to the session and
/// never written to the evidence log.
public final class ProcessTreeTracker {
    public let rootPID: ProcessID

    private var members: Set<ProcessID>
    private var parentOf: [ProcessID: ProcessID] = [:]
    private var executablePathOf: [ProcessID: String?] = [:]

    public init(rootPID: ProcessID) {
        self.rootPID = rootPID
        self.members = [rootPID]
    }

    /// Whether `pid` is the root or a (possibly indirect) descendant of it.
    public func contains(_ pid: ProcessID) -> Bool {
        members.contains(pid)
    }

    public var trackedPIDs: Set<ProcessID> { members }

    /// Feed a full system process snapshot (every process currently
    /// running, not just ones we care about). Returns the pids newly
    /// discovered to belong to the monitored tree in this pass.
    ///
    /// Membership is computed as a transitive closure so that a process
    /// several generations below the root is attributed correctly even if
    /// the intermediate generations were only just observed for the first
    /// time in this same snapshot.
    @discardableResult
    public func absorb(systemProcesses: [ProcessSnapshot]) -> [ProcessID] {
        var byPID: [ProcessID: ProcessSnapshot] = [:]
        for snapshot in systemProcesses {
            byPID[snapshot.pid] = snapshot
            parentOf[snapshot.pid] = snapshot.parentPID
            executablePathOf[snapshot.pid] = snapshot.executablePath
        }

        var newlyDiscovered: [ProcessID] = []
        var changed = true
        while changed {
            changed = false
            for snapshot in systemProcesses where !members.contains(snapshot.pid) {
                if members.contains(snapshot.parentPID) {
                    members.insert(snapshot.pid)
                    newlyDiscovered.append(snapshot.pid)
                    changed = true
                }
            }
        }
        return newlyDiscovered
    }

    /// Record a single newly-observed process directly (used when an event
    /// source such as eslogger reports a fork/exec before the next polling
    /// pass would have picked it up).
    @discardableResult
    public func recordChild(_ pid: ProcessID, parentPID: ProcessID, executablePath: String?) -> Bool {
        parentOf[pid] = parentPID
        executablePathOf[pid] = executablePath
        guard members.contains(parentPID) else { return false }
        members.insert(pid)
        return true
    }

    public func forget(_ pid: ProcessID) {
        guard pid != rootPID else { return }
        members.remove(pid)
    }

    /// Ancestry chain for `pid`, starting at `pid` itself and walking up to
    /// (and including) the root. Used to attach evidence to violations.
    public func ancestry(of pid: ProcessID) -> [AncestryEntry] {
        var chain: [AncestryEntry] = []
        var current: ProcessID? = pid
        var guardCount = 0
        while let c = current, guardCount < 4096 {
            chain.append(AncestryEntry(pid: c, executablePath: executablePathOf[c] ?? nil, sha256: nil))
            if c == rootPID { break }
            current = parentOf[c]
            guardCount += 1
        }
        return chain
    }

    /// All currently-tracked pids in post-order: every descendant appears
    /// before its parent, and the root appears last. This is the order
    /// AppSentinel terminates processes in on a critical violation, so a
    /// parent is never killed while children that could re-parent or spawn
    /// further descendants are still alive.
    public func postOrderPIDs() -> [ProcessID] {
        var childrenOf: [ProcessID: [ProcessID]] = [:]
        for pid in members {
            guard pid != rootPID, let parent = parentOf[pid] else { continue }
            childrenOf[parent, default: []].append(pid)
        }

        var result: [ProcessID] = []
        var visited: Set<ProcessID> = []

        func visit(_ pid: ProcessID) {
            guard members.contains(pid), !visited.contains(pid) else { return }
            visited.insert(pid)
            for child in childrenOf[pid] ?? [] {
                visit(child)
            }
            result.append(pid)
        }

        visit(rootPID)

        // Any tracked pid unreachable from root via recorded parent links
        // (should not normally happen) is still included, before the root.
        for pid in members where !visited.contains(pid) {
            visit(pid)
        }

        return result
    }
}
