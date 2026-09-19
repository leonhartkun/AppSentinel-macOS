import XCTest
@testable import AppSentinelCore

final class ResponsePlanTests: XCTestCase {
    func testCriticalViolationPlanTerminatesDescendantsBeforeRootAndRestoresNetwork() {
        let root = ProcessID(1)
        let tree = ProcessTreeTracker(rootPID: root)
        tree.absorb(systemProcesses: [
            ProcessSnapshot(pid: root, parentPID: ProcessID(0), executablePath: "/root"),
            ProcessSnapshot(pid: ProcessID(2), parentPID: root, executablePath: "/child")
        ])

        let plan = ResponsePlan.forCriticalViolation(reason: "test violation", tree: tree)

        XCTAssertEqual(plan.terminationOrder.last, root)
        XCTAssertTrue(plan.terminationOrder.contains(ProcessID(2)))
        XCTAssertTrue(plan.shouldRestoreNetworkState)
        XCTAssertEqual(plan.reason, "test violation")
    }
}
