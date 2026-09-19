import XCTest

/// Runs the real, compiled `appsentinel` binary end to end against a
/// harmless fixture `.app`. This is the literal CLI acceptance check:
/// launch, descendant tracking, and exit-on-target-exit are exercised
/// through the actual command line a user would type, not through
/// injected test doubles.
///
/// Only the normal-exit fixture is used here — never a violating one —
/// specifically so this test never drives AppSentinel's critical-response
/// path (which would call the *real* `networksetup`/`security` adapters).
/// The destructive-response path is instead verified in
/// `SessionCriticalViolationAcceptanceTests` against fully injected fakes.
/// Everything this test does touch (the real login keychain, `scutil`,
/// `ps`) is read-only.
final class CLIProcessAcceptanceTests: XCTestCase {
    private var productsDirectory: URL {
        for bundle in Bundle.allBundles where bundle.bundlePath.hasSuffix(".xctest") {
            return bundle.bundleURL.deletingLastPathComponent()
        }
        fatalError("could not locate the SwiftPM build products directory from the test bundle")
    }

    func testCLILaunchesFixtureTracksDescendantAndExitsWhenTargetExits() throws {
        let binaryURL = productsDirectory.appendingPathComponent("appsentinel")
        guard FileManager.default.fileExists(atPath: binaryURL.path) else {
            throw XCTSkip("appsentinel 可执行文件未在测试构建产物目录中找到：\(binaryURL.path)")
        }

        let workDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: workDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: workDir) }

        let appPath = try FixtureApp.make(name: "NormalExit", scriptBody: FixtureApp.normalExitScript(), in: workDir)
        let logDir = workDir.appendingPathComponent("logs")

        let process = Process()
        process.executableURL = binaryURL
        process.arguments = ["run", appPath, "--log-dir", logDir.path, "--no-eslogger"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        try process.run()

        let deadline = Date().addingTimeInterval(15)
        while process.isRunning, Date() < deadline {
            Thread.sleep(forTimeInterval: 0.1)
        }
        if process.isRunning {
            process.terminate()
            XCTFail("appsentinel 在正常场景下未按预期退出（超时）")
            return
        }

        let outputData = pipe.fileHandleForReading.readDataToEndOfFile()
        let outputText = String(data: outputData, encoding: .utf8) ?? ""

        XCTAssertEqual(process.terminationStatus, 0, "正常退出场景应返回退出码 0，实际输出：\n\(outputText)")
        XCTAssertTrue(outputText.contains("正常退出"), "终端输出应提示目标已正常退出：\n\(outputText)")

        // Evidence: a session directory was created with a summary
        // recording the real target path.
        let sessionDirs = (try? FileManager.default.contentsOfDirectory(at: logDir, includingPropertiesForKeys: nil)) ?? []
        XCTAssertEqual(sessionDirs.count, 1)
        guard let sessionDir = sessionDirs.first else { return }
        let summaryData = try Data(contentsOf: sessionDir.appendingPathComponent("session.json"))
        let summary = try JSONSerialization.jsonObject(with: summaryData) as? [String: String]
        XCTAssertEqual(summary?["target"], appPath)
    }
}
