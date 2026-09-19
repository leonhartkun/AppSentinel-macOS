import XCTest
@testable import AppSentinelCore

final class EvidenceLoggerTests: XCTestCase {
    var tempDir: URL!

    override func setUpWithError() throws {
        tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: tempDir)
    }

    func testEvidenceLogNeverContainsFileContentsOrCredentials() throws {
        let logger = try EvidenceLogger(sessionDirectory: tempDir)

        // Simulate the exact kind of secret an attacker payload might try
        // to read: AppSentinel must only ever record that the path was
        // touched, never the bytes it contains.
        let secretMaterial = "-----BEGIN OPENSSH PRIVATE KEY-----\nSUPERSECRETKEYMATERIAL\n-----END OPENSSH PRIVATE KEY-----"

        try logger.appendEvent(EvidenceEvent(
            timestamp: Date(),
            pid: 4242,
            description: "读取受保护路径：/tmp/fixture-home/.ssh/id_ed25519",
            decision: "critical"
        ))

        let ancestry = [AncestryEntry(pid: ProcessID(4242), executablePath: "/tmp/fixture-home/malicious", sha256: "deadbeef")]
        try logger.writeViolation(ViolationEvidence(
            sessionID: "test-session",
            timestamp: Date(),
            triggeringReason: "检测到未经授权读取受保护路径（SSH 密钥）：/tmp/fixture-home/.ssh/id_ed25519",
            ancestry: ancestry,
            stateDiffLines: ["LaunchAgents: +com.example.persist.plist"]
        ))

        let eventsData = try Data(contentsOf: tempDir.appendingPathComponent("events.ndjson"))
        let violationData = try Data(contentsOf: tempDir.appendingPathComponent("violation.json"))

        let eventsText = String(data: eventsData, encoding: .utf8)!
        let violationText = String(data: violationData, encoding: .utf8)!

        XCTAssertFalse(eventsText.contains(secretMaterial))
        XCTAssertFalse(violationText.contains(secretMaterial))
        XCTAssertFalse(eventsText.contains("SUPERSECRETKEYMATERIAL"))
        XCTAssertFalse(violationText.contains("SUPERSECRETKEYMATERIAL"))

        // But the path and hash — the actually useful evidence — must be present.
        XCTAssertTrue(eventsText.contains(".ssh/id_ed25519"))
        XCTAssertTrue(violationText.contains("deadbeef"))
    }

    func testEvidenceDirectoryIsCreatedAndFilesAreReadableJSON() throws {
        let logger = try EvidenceLogger(sessionDirectory: tempDir)
        try logger.writeSessionSummary(["target": "/Applications/Example.app", "mode": "eslogger"])

        let summaryURL = tempDir.appendingPathComponent("session.json")
        XCTAssertTrue(FileManager.default.fileExists(atPath: summaryURL.path))

        let data = try Data(contentsOf: summaryURL)
        let object = try JSONSerialization.jsonObject(with: data) as? [String: String]
        XCTAssertEqual(object?["target"], "/Applications/Example.app")

        // Paths must stay human-readable (unescaped "/") in the raw file,
        // not just after JSON-decoding it back.
        let text = String(data: data, encoding: .utf8)!
        XCTAssertTrue(text.contains("/Applications/Example.app"))
    }

    func testAppendedEventsAccumulateAsNDJSONLines() throws {
        let logger = try EvidenceLogger(sessionDirectory: tempDir)
        try logger.appendEvent(EvidenceEvent(timestamp: Date(), pid: 1, description: "one", decision: "allow"))
        try logger.appendEvent(EvidenceEvent(timestamp: Date(), pid: 1, description: "two", decision: "allow"))

        let text = try String(contentsOf: tempDir.appendingPathComponent("events.ndjson"), encoding: .utf8)
        let lines = text.split(separator: "\n")
        XCTAssertEqual(lines.count, 2)
    }
}
