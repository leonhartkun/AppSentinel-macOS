import XCTest
@testable import AppSentinelCore

final class SensitivePathPolicyTests: XCTestCase {
    let home = "/tmp/appsentinel-fixture-home"

    func testClassifierIdentifiesProtectedCategories() {
        let classifier = SensitivePathClassifier(homeDirectory: home)

        XCTAssertEqual(classifier.classify("\(home)/.ssh/id_ed25519"), .sshPrivateKey)
        XCTAssertEqual(classifier.classify("\(home)/Library/Application Support/Google/Chrome/Default/Login Data"), .browserCredentialStore)
        XCTAssertEqual(classifier.classify("\(home)/Library/Keychains/login.keychain-db"), .keychainFile)
        XCTAssertEqual(classifier.classify("\(home)/Library/LaunchAgents/com.example.agent.plist"), .launchPersistence)
        XCTAssertEqual(classifier.classify("/Library/LaunchDaemons/com.example.daemon.plist"), .launchPersistence)
        XCTAssertNil(classifier.classify("\(home)/Documents/notes.txt"))
    }

    func testReadOfProtectedPathIsCriticalByDefault() {
        var enrollment: CertificateEnrollmentWindow? = nil
        let event = SecurityEvent(
            pid: ProcessID(1),
            timestamp: Date(),
            kind: .sensitivePathRead(path: "\(home)/.ssh/id_ed25519", category: .sshPrivateKey)
        )
        let decision = PolicyEvaluator.evaluate(event, policy: .empty, enrollment: &enrollment)

        guard case .critical(let reason) = decision else {
            return XCTFail("expected critical decision, got \(decision)")
        }
        XCTAssertTrue(reason.contains("SSH"))
    }

    func testWriteOfProtectedPathIsCriticalByDefault() {
        var enrollment: CertificateEnrollmentWindow? = nil
        let event = SecurityEvent(
            pid: ProcessID(1),
            timestamp: Date(),
            kind: .sensitivePathWrite(path: "\(home)/Library/LaunchAgents/com.example.agent.plist", category: .launchPersistence)
        )
        let decision = PolicyEvaluator.evaluate(event, policy: .empty, enrollment: &enrollment)

        guard case .critical = decision else {
            return XCTFail("expected critical decision, got \(decision)")
        }
    }

    func testExplicitExceptionAllowsProtectedPathAccess() {
        var enrollment: CertificateEnrollmentWindow? = nil
        let path = "\(home)/.ssh/known_hosts_test"
        var policy = SecurityPolicy.empty
        policy.protectedPathExceptions.insert(path)

        let event = SecurityEvent(pid: ProcessID(1), timestamp: Date(), kind: .sensitivePathRead(path: path, category: .sshPrivateKey))
        let decision = PolicyEvaluator.evaluate(event, policy: policy, enrollment: &enrollment)

        XCTAssertEqual(decision, .allow)
    }
}
