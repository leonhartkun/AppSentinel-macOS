import XCTest
@testable import AppSentinelCore

final class ProcessTreeTrackerTests: XCTestCase {
    func testOnlyRootAndDescendantsAreAttributed() {
        let root = ProcessID(100)
        let tracker = ProcessTreeTracker(rootPID: root)

        let systemSnapshot: [ProcessSnapshot] = [
            ProcessSnapshot(pid: ProcessID(1), parentPID: ProcessID(0), executablePath: "/sbin/launchd"),
            ProcessSnapshot(pid: root, parentPID: ProcessID(1), executablePath: "/Applications/Example.app/Contents/MacOS/Example"),
            ProcessSnapshot(pid: ProcessID(200), parentPID: ProcessID(1), executablePath: "/usr/libexec/some_unrelated_daemon"),
            ProcessSnapshot(pid: ProcessID(101), parentPID: root, executablePath: "/bin/helper")
        ]

        let newlyDiscovered = tracker.absorb(systemProcesses: systemSnapshot)

        XCTAssertTrue(tracker.contains(root))
        XCTAssertTrue(tracker.contains(ProcessID(101)))
        XCTAssertFalse(tracker.contains(ProcessID(200)), "unrelated system process must never be attributed to the session")
        XCTAssertFalse(tracker.contains(ProcessID(1)))
        XCTAssertEqual(Set(newlyDiscovered), [ProcessID(101)])
    }

    func testMultiLevelDescendantsAreTrackedTransitively() {
        let root = ProcessID(1)
        let tracker = ProcessTreeTracker(rootPID: root)

        // Deliberately out of "natural" order to prove the closure is
        // computed correctly regardless of array ordering: grandchild and
        // great-grandchild appear before their parents in this snapshot.
        let snapshot: [ProcessSnapshot] = [
            ProcessSnapshot(pid: ProcessID(4), parentPID: ProcessID(3), executablePath: "/bin/great_grandchild"),
            ProcessSnapshot(pid: ProcessID(3), parentPID: ProcessID(2), executablePath: "/bin/grandchild"),
            ProcessSnapshot(pid: ProcessID(2), parentPID: root, executablePath: "/bin/child"),
            ProcessSnapshot(pid: root, parentPID: ProcessID(0), executablePath: "/Applications/Example.app/Contents/MacOS/Example")
        ]

        tracker.absorb(systemProcesses: snapshot)

        XCTAssertTrue(tracker.contains(ProcessID(2)))
        XCTAssertTrue(tracker.contains(ProcessID(3)))
        XCTAssertTrue(tracker.contains(ProcessID(4)))
        XCTAssertEqual(tracker.trackedPIDs, [root, ProcessID(2), ProcessID(3), ProcessID(4)])
    }

    func testDescendantsAreObservedAcrossMultiplePollingPasses() {
        let root = ProcessID(1)
        let tracker = ProcessTreeTracker(rootPID: root)

        tracker.absorb(systemProcesses: [
            ProcessSnapshot(pid: root, parentPID: ProcessID(0), executablePath: "/root")
        ])
        tracker.absorb(systemProcesses: [
            ProcessSnapshot(pid: root, parentPID: ProcessID(0), executablePath: "/root"),
            ProcessSnapshot(pid: ProcessID(2), parentPID: root, executablePath: "/child")
        ])
        tracker.absorb(systemProcesses: [
            ProcessSnapshot(pid: root, parentPID: ProcessID(0), executablePath: "/root"),
            ProcessSnapshot(pid: ProcessID(2), parentPID: root, executablePath: "/child"),
            ProcessSnapshot(pid: ProcessID(3), parentPID: ProcessID(2), executablePath: "/grandchild")
        ])

        XCTAssertEqual(tracker.trackedPIDs, [root, ProcessID(2), ProcessID(3)])
    }

    func testTerminationOrderKillsDescendantsBeforeRoot() {
        let root = ProcessID(1)
        let tracker = ProcessTreeTracker(rootPID: root)

        tracker.absorb(systemProcesses: [
            ProcessSnapshot(pid: root, parentPID: ProcessID(0), executablePath: "/root"),
            ProcessSnapshot(pid: ProcessID(2), parentPID: root, executablePath: "/child-a"),
            ProcessSnapshot(pid: ProcessID(3), parentPID: root, executablePath: "/child-b"),
            ProcessSnapshot(pid: ProcessID(4), parentPID: ProcessID(2), executablePath: "/grandchild")
        ])

        let order = tracker.postOrderPIDs()

        XCTAssertEqual(order.last, root, "root must be terminated last")
        XCTAssertTrue(order.firstIndex(of: ProcessID(4))! < order.firstIndex(of: ProcessID(2))!,
                       "grandchild must be terminated before its parent")
        XCTAssertTrue(order.firstIndex(of: ProcessID(2))! < order.firstIndex(of: root)!)
        XCTAssertTrue(order.firstIndex(of: ProcessID(3))! < order.firstIndex(of: root)!)
        XCTAssertEqual(Set(order), tracker.trackedPIDs)
    }

    func testAncestryChainWalksToRoot() {
        let root = ProcessID(1)
        let tracker = ProcessTreeTracker(rootPID: root)
        tracker.absorb(systemProcesses: [
            ProcessSnapshot(pid: root, parentPID: ProcessID(0), executablePath: "/root"),
            ProcessSnapshot(pid: ProcessID(2), parentPID: root, executablePath: "/child"),
            ProcessSnapshot(pid: ProcessID(3), parentPID: ProcessID(2), executablePath: "/grandchild")
        ])

        let chain = tracker.ancestry(of: ProcessID(3))
        XCTAssertEqual(chain.map(\.pid), [ProcessID(3), ProcessID(2), root])
    }
}
