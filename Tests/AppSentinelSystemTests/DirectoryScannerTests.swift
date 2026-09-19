import XCTest
@testable import AppSentinelSystem
import AppSentinelCore

final class DirectoryScannerTests: XCTestCase {
    var tempDir: URL!

    override func setUpWithError() throws {
        tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: tempDir)
    }

    func testScanFindsFilesAndDetectsChangesAcrossPasses() throws {
        let scanner = DirectoryScanner()
        let filePath = tempDir.appendingPathComponent("com.example.agent.plist")
        try "placeholder".write(to: filePath, atomically: true, encoding: .utf8)

        let before = scanner.scan(directories: [tempDir.path])
        XCTAssertNotNil(before.modificationTimeByPath[filePath.path])

        // Force a detectably different modification time.
        try FileManager.default.setAttributes([.modificationDate: Date().addingTimeInterval(10)], ofItemAtPath: filePath.path)
        let after = scanner.scan(directories: [tempDir.path])

        let changes = StateSnapshotDiff.diff(before: before, after: after)
        XCTAssertTrue(changes.contains { $0.path == filePath.path && $0.kind == .modified })
    }

    func testScanIgnoresNonexistentDirectories() {
        let scanner = DirectoryScanner()
        let snapshot = scanner.scan(directories: ["/nonexistent/appsentinel-fixture"])
        XCTAssertTrue(snapshot.modificationTimeByPath.isEmpty)
    }

    func testScanRecursesIntoSubdirectories() throws {
        let subdir = tempDir.appendingPathComponent("Default")
        try FileManager.default.createDirectory(at: subdir, withIntermediateDirectories: true)
        let filePath = subdir.appendingPathComponent("Login Data")
        try "placeholder".write(to: filePath, atomically: true, encoding: .utf8)

        let scanner = DirectoryScanner()
        let snapshot = scanner.scan(directories: [tempDir.path])
        XCTAssertNotNil(snapshot.modificationTimeByPath[filePath.path])
    }
}
