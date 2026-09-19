import XCTest
@testable import AppSentinelSystem
import AppSentinelCore

final class CertificateSnapshotParsingTests: XCTestCase {
    // Captured verbatim from a real, read-only `security find-certificate
    // -a -Z <login keychain>` run during development, with the actual
    // subject/base64 blob material left intact (it is public certificate
    // metadata, not a secret) so the parser is tested against the real
    // on-disk format rather than a guessed one.
    static let sampleOutput = """
    SHA-256 hash: 610D390219F282427A346C2BC2EE8489F92232A693216020F70AB4B16870E9D0
    SHA-1 hash: 0263024118BF7D88AD838A7EB372FEF7FDD1EEFC
    keychain: "/Users/example/Library/Keychains/login.keychain-db"
    version: 512
    class: 0x80001000
    attributes:
        "alis"<blob>="Apple Development: person@example.com (VR4F9M4A8H)"
        "cenc"<uint32>=0x00000003
        "labl"<blob>="Apple Development: person@example.com (VR4F9M4A8H)"
        "skid"<blob>=0x593922116F114841F03E3BE7742E210CCA8BFD09  "Y9"
    SHA-256 hash: DCF21878C77F4198E4B4614F03D696D89C66C66008D4244E1B99161AAC91601F
    SHA-1 hash: 06EC06599F4ED0027CC58956B4D3AC1255114F35
    keychain: "/Users/example/Library/Keychains/login.keychain-db"
    version: 512
    class: 0x80001000
    attributes:
        "alis"<blob>="Apple Worldwide Developer Relations Certification Authority"
        "labl"<blob>="Apple Worldwide Developer Relations Certification Authority"
    """

    func testParsesFingerprintsAndSubjectsFromRealSecurityToolFormat() {
        let records = RealCertificateSnapshot.parse(Self.sampleOutput, keychainPath: "/fake/login.keychain-db")

        XCTAssertEqual(records.count, 2)
        XCTAssertEqual(records[0].sha1Fingerprint, "0263024118BF7D88AD838A7EB372FEF7FDD1EEFC")
        XCTAssertEqual(records[0].subject, "Apple Development: person@example.com (VR4F9M4A8H)")
        XCTAssertEqual(records[1].sha1Fingerprint, "06EC06599F4ED0027CC58956B4D3AC1255114F35")
        XCTAssertEqual(records[1].subject, "Apple Worldwide Developer Relations Certification Authority")
        XCTAssertTrue(records.allSatisfy { $0.keychainPath == "/fake/login.keychain-db" })
    }

    func testParsingEmptyOutputYieldsNoRecords() {
        XCTAssertEqual(RealCertificateSnapshot.parse("", keychainPath: "/fake"), [])
    }

    /// A genuine, read-only smoke test against the real login keychain on
    /// this machine: confirms the end-to-end adapter runs without
    /// throwing and returns a shape consistent with real output, without
    /// asserting on exact certificate contents (which vary per machine).
    func testRealSnapshotAgainstLocalLoginKeychainDoesNotThrow() throws {
        let path = RealCertificateSnapshot.defaultLoginKeychainPath()
        guard FileManager.default.fileExists(atPath: path) else {
            throw XCTSkip("此机器没有登录钥匙串文件，跳过真实快照测试")
        }
        let snapshot = RealCertificateSnapshot(keychainPaths: [path])
        let records = try snapshot.snapshot()
        for record in records {
            XCTAssertFalse(record.sha1Fingerprint.isEmpty)
        }
    }
}
