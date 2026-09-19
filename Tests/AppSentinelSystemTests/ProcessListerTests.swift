import XCTest
@testable import AppSentinelSystem
import AppSentinelCore

final class ProcessListerTests: XCTestCase {
    /// Real integration test against the actual system process table.
    func testRealProcessListerFindsOwnProcess() throws {
        let lister = RealProcessLister()
        let processes = try lister.currentProcesses()

        let selfPID = ProcessID(ProcessInfo.processInfo.processIdentifier)
        XCTAssertTrue(processes.contains { $0.pid == selfPID })
        XCTAssertFalse(processes.isEmpty)
    }

    func testRealTerminatorReportsLivenessOfLaunchedAndExitedProcess() throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sleep")
        process.arguments = ["30"]
        try process.run()
        let pid = ProcessID(process.processIdentifier)

        let terminator = RealProcessTerminator()
        XCTAssertTrue(terminator.isAlive(pid))

        try terminator.terminate(pid, signal: SIGKILL)
        process.waitUntilExit()

        // Give the kernel a moment to fully reap/report the exit.
        let deadline = Date().addingTimeInterval(2)
        while terminator.isAlive(pid), Date() < deadline {
            Thread.sleep(forTimeInterval: 0.05)
        }
        XCTAssertFalse(terminator.isAlive(pid))
    }
}
