import XCTest
@testable import AppSentinelSystem
import AppSentinelCore

final class ESLoggerEventSourceParsingTests: XCTestCase {
    // Deliberately NOT under /tmp: several fixtures below assert that a
    // path *outside* any watched location is ignored, and /tmp itself is
    // treated as a drop-candidate location for unclassified paths.
    let classifier = SensitivePathClassifier(homeDirectory: "/private/var/fixture-home")

    private func parse(_ json: String) -> SecurityEvent? {
        ESLoggerEventSource.parseLine(json.data(using: .utf8)!, classifier: classifier)
    }

    func testParsesExecEventWithDirectPIDField() {
        let json = """
        {"event_type":9,"process":{"pid":100,"executable":{"path":"/bin/zsh"}},
         "event":{"exec":{"target":{"pid":200,"executable":{"path":"/bin/bash"},"args":["bash","-c","echo hi"]}}}}
        """
        guard let event = parse(json), case .processExec(let path, let args, _) = event.kind else {
            return XCTFail("expected processExec event")
        }
        XCTAssertEqual(event.pid, ProcessID(200))
        XCTAssertEqual(path, "/bin/bash")
        XCTAssertEqual(args, ["bash", "-c", "echo hi"])
    }

    func testParsesPIDFromAuditTokenValArrayFallback() {
        // Some macOS versions serialize the audit token as a raw BSD
        // token array rather than a convenience `pid` field; index 5 is
        // the pid per `audit_token_to_pid`.
        let json = """
        {"process":{"audit_token":{"val":[0,0,0,0,0,4242,0,0]},"executable":{"path":"/bin/zsh"}},
         "event":{"exit":{"stat":0}}}
        """
        guard let event = parse(json), case .processExit = event.kind else {
            return XCTFail("expected processExit event")
        }
        XCTAssertEqual(event.pid, ProcessID(4242))
    }

    func testParsesForkEventChildPID() {
        let json = """
        {"process":{"pid":10},
         "event":{"fork":{"child":{"pid":11,"executable":{"path":"/bin/zsh"}}}}}
        """
        guard let event = parse(json), case .processFork(let childPID) = event.kind else {
            return XCTFail("expected processFork event")
        }
        XCTAssertEqual(event.pid, ProcessID(10))
        XCTAssertEqual(childPID, ProcessID(11))
    }

    func testParsesCreateEventOnSensitivePathAsWrite() {
        let json = """
        {"process":{"pid":10},
         "event":{"create":{"destination":{"existing_file":{"path":"/private/var/fixture-home/.ssh/id_ed25519"}}}}}
        """
        guard let event = parse(json), case .sensitivePathWrite(let path, let category) = event.kind else {
            return XCTFail("expected sensitivePathWrite event")
        }
        XCTAssertEqual(path, "/private/var/fixture-home/.ssh/id_ed25519")
        XCTAssertEqual(category, .sshPrivateKey)
    }

    func testParsesCreateEventOnNewPathShapeUnderLaunchAgents() {
        let json = """
        {"process":{"pid":10},
         "event":{"create":{"destination":{"new_path":{"dir":{"path":"/private/var/fixture-home/Library/LaunchAgents"},"filename":"com.example.plist"}}}}}
        """
        guard let event = parse(json), case .sensitivePathWrite(let path, let category) = event.kind else {
            return XCTFail("expected sensitivePathWrite event")
        }
        XCTAssertEqual(path, "/private/var/fixture-home/Library/LaunchAgents/com.example.plist")
        XCTAssertEqual(category, .launchPersistence)
    }

    func testParsesUnlinkEventOnSensitivePath() {
        let json = """
        {"process":{"pid":10},
         "event":{"unlink":{"target":{"path":"/private/var/fixture-home/.ssh/known_hosts"}}}}
        """
        guard let event = parse(json), case .sensitivePathWrite(let path, _) = event.kind else {
            return XCTFail("expected sensitivePathWrite event")
        }
        XCTAssertEqual(path, "/private/var/fixture-home/.ssh/known_hosts")
    }

    func testCreateEventOutsideAnyWatchedLocationAndOutsideTempIsIgnored() {
        let json = """
        {"process":{"pid":10},
         "event":{"create":{"destination":{"existing_file":{"path":"/private/var/fixture-home/Documents/notes.txt"}}}}}
        """
        XCTAssertNil(parse(json))
    }

    func testMalformedJSONReturnsNilInsteadOfCrashing() {
        XCTAssertNil(parse("not json at all"))
        XCTAssertNil(parse("{}"))
    }
}
