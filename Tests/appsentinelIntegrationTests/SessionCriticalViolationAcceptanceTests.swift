import XCTest
import Darwin
import AppSentinelCore
import AppSentinelSystem
@testable import appsentinel

/// Fully synthetic certificate/network adapters, so this suite can drive a
/// genuine critical-violation-and-response cycle — including the recovery
/// step that would otherwise call `networksetup` — without ever touching
/// the real system's certificates or proxy configuration. Process
/// listing/termination/hashing stay real, because the whole point of this
/// test is to prove AppSentinel actually kills its (harmless, fixture)
/// monitored tree.
private final class FakeCertificateSnapshotting: CertificateSnapshotting, @unchecked Sendable {
    func snapshot() throws -> [CertificateRecord] { [] }
}

private final class FakeNetworkStateSnapshotting: NetworkStateSnapshotting, @unchecked Sendable {
    let lock = NSLock()
    private(set) var restoreCallCount = 0
    func snapshot() throws -> NetworkState { NetworkState(httpProxy: nil, httpsProxy: nil, dnsServers: [], defaultRouteGateway: nil) }
    func restoreProxy(from state: NetworkState) throws {
        lock.lock(); restoreCallCount += 1; lock.unlock()
    }
    func restoreWasCalled() -> Bool {
        lock.lock(); defer { lock.unlock() }
        return restoreCallCount > 0
    }
}

private struct FakeSensitivePathProviding: SensitivePathProviding {
    let homeDirectory: String
    let watchedDirectories: [String]
}

final class SessionCriticalViolationAcceptanceTests: XCTestCase {
    var workDir: URL!

    override func setUpWithError() throws {
        workDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: workDir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: workDir)
    }

    func testViolatingFixtureTreeIsTerminatedAndEvidenceIsWrittenWithoutTouchingRealSystem() throws {
        let sensitiveHome = workDir.appendingPathComponent("fake-home")
        try FileManager.default.createDirectory(at: sensitiveHome, withIntermediateDirectories: true)

        let rootPIDFile = workDir.appendingPathComponent("root.pid").path
        let grandchildPIDFile = workDir.appendingPathComponent("grandchild.pid").path
        let appPath = try FixtureApp.make(
            name: "Violator",
            scriptBody: FixtureApp.protectedPathViolationScript(
                sensitiveHome: sensitiveHome.path,
                rootPIDFile: rootPIDFile,
                grandchildPIDFile: grandchildPIDFile
            ),
            in: workDir
        )

        let network = FakeNetworkStateSnapshotting()
        let dependencies = SessionDependencies(
            processListing: RealProcessLister(),
            terminator: RealProcessTerminator(),
            hasher: RealExecutableHasher(),
            certificateSnapshotting: FakeCertificateSnapshotting(),
            networkStateSnapshotting: network,
            sensitivePathProviding: FakeSensitivePathProviding(
                homeDirectory: sensitiveHome.path,
                watchedDirectories: [sensitiveHome.appendingPathComponent(".ssh").path]
            )
        )

        var options = RunOptions(appBundlePath: appPath)
        options.logDirectory = workDir.appendingPathComponent("logs").path
        options.forcePolling = true

        let session = Session(options: options, dependencies: dependencies)

        let resultLock = NSLock()
        var exitCode: Int32?
        Thread {
            let code = session.run()
            resultLock.lock(); exitCode = code; resultLock.unlock()
        }.start()

        let deadline = Date().addingTimeInterval(20)
        while Date() < deadline {
            resultLock.lock(); let done = exitCode != nil; resultLock.unlock()
            if done { break }
            Thread.sleep(forTimeInterval: 0.1)
        }

        resultLock.lock()
        let finalExitCode = exitCode
        resultLock.unlock()

        guard let finalExitCode else {
            XCTFail("Session 未在超时时间内完成响应")
            return
        }
        XCTAssertEqual(finalExitCode, 2, "检测到严重违规时退出码应为 2")

        // The fixture wrote its own pid and its grandchild's pid to disk
        // at startup; the grandchild sleeps for 60s on its own, so it
        // being dead here is direct proof AppSentinel actually terminated
        // the monitored tree rather than the fixture merely finishing.
        func readPID(_ path: String) -> pid_t? {
            guard let text = try? String(contentsOfFile: path, encoding: .utf8) else { return nil }
            return pid_t(text.trimmingCharacters(in: .whitespacesAndNewlines))
        }
        guard let rootPID = readPID(rootPIDFile), let grandchildPID = readPID(grandchildPIDFile) else {
            XCTFail("未能读取 fixture 写入的 pid 文件")
            return
        }
        XCTAssertNotEqual(kill(rootPID, 0), 0, "根进程应已被终止")
        XCTAssertNotEqual(kill(grandchildPID, 0), 0, "长期休眠的孙进程应已被终止，证明子进程优先终止策略生效")

        XCTAssertTrue(network.restoreWasCalled(), "严重违规应尝试恢复启动前的网络代理设置（在本测试中是伪造的适配器，从未触碰真实系统）")

        let logDirs = try FileManager.default.contentsOfDirectory(at: URL(fileURLWithPath: options.logDirectory!), includingPropertiesForKeys: nil)
        XCTAssertEqual(logDirs.count, 1)
        guard let sessionDir = logDirs.first else { return }

        let violationData = try Data(contentsOf: sessionDir.appendingPathComponent("violation.json"))
        let violationText = String(data: violationData, encoding: .utf8) ?? ""
        XCTAssertTrue(violationText.contains("SSH"), "证据应说明触发原因涉及 SSH 密钥：\(violationText)")
        XCTAssertFalse(violationText.contains("fake-key-material-not-a-real-secret"), "证据绝不能包含文件内容")

        // Confirm nothing under this fake home escaped into paths that
        // could be confused with the real user's actual ~/.ssh.
        XCTAssertTrue(sensitiveHome.path.hasPrefix(workDir.path))
    }
}
