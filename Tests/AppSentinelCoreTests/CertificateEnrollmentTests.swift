import XCTest
@testable import AppSentinelCore

final class CertificateEnrollmentTests: XCTestCase {
    private func makeCert(_ name: String) -> CertificateRecord {
        CertificateRecord(sha1Fingerprint: name, subject: "CN=\(name)", keychainPath: "/tmp/fake.keychain")
    }

    func testFirstCertificateWithinFiveMinuteWindowIsAllowed() {
        let start = Date(timeIntervalSince1970: 1_000_000)
        var window: CertificateEnrollmentWindow? = CertificateEnrollmentWindow(start: start, duration: 5 * 60)
        let policy = SecurityPolicy.empty

        let event = SecurityEvent(
            pid: ProcessID(1),
            timestamp: start.addingTimeInterval(60),
            kind: .certificateAdded(makeCert("first"))
        )

        let decision = PolicyEvaluator.evaluate(event, policy: policy, enrollment: &window)

        XCTAssertEqual(decision, .allow)
        XCTAssertEqual(window?.enrolledCount, 1)
    }

    func testSecondCertificateInsideWindowIsImmediatelyCritical() {
        let start = Date(timeIntervalSince1970: 1_000_000)
        var window: CertificateEnrollmentWindow? = CertificateEnrollmentWindow(start: start, duration: 5 * 60)
        let policy = SecurityPolicy.empty

        let first = SecurityEvent(pid: ProcessID(1), timestamp: start.addingTimeInterval(10), kind: .certificateAdded(makeCert("first")))
        _ = PolicyEvaluator.evaluate(first, policy: policy, enrollment: &window)

        let second = SecurityEvent(pid: ProcessID(1), timestamp: start.addingTimeInterval(20), kind: .certificateAdded(makeCert("second")))
        let decision = PolicyEvaluator.evaluate(second, policy: policy, enrollment: &window)

        guard case .critical(let reason) = decision else {
            return XCTFail("expected critical decision, got \(decision)")
        }
        XCTAssertTrue(reason.contains("第二张"))
    }

    func testCertificateOutsideEnrollmentWindowIsCritical() {
        let start = Date(timeIntervalSince1970: 1_000_000)
        var window: CertificateEnrollmentWindow? = CertificateEnrollmentWindow(start: start, duration: 5 * 60)
        let policy = SecurityPolicy.empty

        let event = SecurityEvent(
            pid: ProcessID(1),
            timestamp: start.addingTimeInterval(5 * 60 + 1),
            kind: .certificateAdded(makeCert("late"))
        )

        let decision = PolicyEvaluator.evaluate(event, policy: policy, enrollment: &window)

        guard case .critical(let reason) = decision else {
            return XCTFail("expected critical decision, got \(decision)")
        }
        XCTAssertTrue(reason.contains("登记窗口之外"))
    }

    func testCertificateWithNoEnrollmentWindowAtAllIsCritical() {
        var window: CertificateEnrollmentWindow? = nil
        let policy = SecurityPolicy.empty

        let event = SecurityEvent(pid: ProcessID(1), timestamp: Date(), kind: .certificateAdded(makeCert("unexpected")))
        let decision = PolicyEvaluator.evaluate(event, policy: policy, enrollment: &window)

        guard case .critical = decision else {
            return XCTFail("expected critical decision, got \(decision)")
        }
    }

    func testCertificateBeforeWindowStartIsCritical() {
        let start = Date(timeIntervalSince1970: 1_000_000)
        var window: CertificateEnrollmentWindow? = CertificateEnrollmentWindow(start: start, duration: 5 * 60)
        let policy = SecurityPolicy.empty

        let event = SecurityEvent(pid: ProcessID(1), timestamp: start.addingTimeInterval(-1), kind: .certificateAdded(makeCert("early")))
        let decision = PolicyEvaluator.evaluate(event, policy: policy, enrollment: &window)

        guard case .critical = decision else {
            return XCTFail("expected critical decision, got \(decision)")
        }
    }
}
