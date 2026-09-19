import XCTest
@testable import AppSentinelCore

final class StateSnapshotDiffTests: XCTestCase {
    func testDetectsCreatedModifiedAndRemovedPaths() {
        let t0 = Date(timeIntervalSince1970: 0)
        let t1 = Date(timeIntervalSince1970: 100)

        let before = DirectorySnapshot(modificationTimeByPath: [
            "/a": t0,
            "/b": t0
        ])
        let after = DirectorySnapshot(modificationTimeByPath: [
            "/a": t1, // modified
            "/c": t0  // created; "/b" removed
        ])

        let changes = StateSnapshotDiff.diff(before: before, after: after)
        let byPath = Dictionary(uniqueKeysWithValues: changes.map { ($0.path, $0.kind) })

        XCTAssertEqual(byPath["/a"], .modified)
        XCTAssertEqual(byPath["/c"], .created)
        XCTAssertEqual(byPath["/b"], .removed)
    }

    func testCertificateDiffByFingerprint() {
        let common = CertificateRecord(sha1Fingerprint: "AAA", subject: "CN=common", keychainPath: "/k")
        let removedCert = CertificateRecord(sha1Fingerprint: "BBB", subject: "CN=removed", keychainPath: "/k")
        let addedCert = CertificateRecord(sha1Fingerprint: "CCC", subject: "CN=added", keychainPath: "/k")

        let result = StateSnapshotDiff.diffCertificates(before: [common, removedCert], after: [common, addedCert])

        XCTAssertEqual(result.added, [addedCert])
        XCTAssertEqual(result.removed, [removedCert])
    }
}
