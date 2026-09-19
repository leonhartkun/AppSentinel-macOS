import XCTest
@testable import AppSentinelSystem
import AppSentinelCore

// Mutated from the test thread while PollingEventSource reads on its own
// queue; the lock (not the compiler) is what makes that safe, so these
// opt out of automatic Sendable checking rather than pretending to be
// immutable.
private final class FakeProcessListing: ProcessListing, @unchecked Sendable {
    let lock = NSLock()
    var processes: [ProcessSnapshot]
    init(processes: [ProcessSnapshot]) { self.processes = processes }
    func currentProcesses() throws -> [ProcessSnapshot] {
        lock.lock(); defer { lock.unlock() }
        return processes
    }
}

private final class FakeCertificateSnapshotting: CertificateSnapshotting, @unchecked Sendable {
    let lock = NSLock()
    var certificates: [CertificateRecord]
    init(certificates: [CertificateRecord]) { self.certificates = certificates }
    func snapshot() throws -> [CertificateRecord] {
        lock.lock(); defer { lock.unlock() }
        return certificates
    }
}

private final class FakeNetworkStateSnapshotting: NetworkStateSnapshotting, @unchecked Sendable {
    let lock = NSLock()
    var state: NetworkState
    init(state: NetworkState) { self.state = state }
    func snapshot() throws -> NetworkState {
        lock.lock(); defer { lock.unlock() }
        return state
    }
    func restoreProxy(from state: NetworkState) throws {}
}

private struct FakeSensitivePathProviding: SensitivePathProviding {
    let homeDirectory: String
    let watchedDirectories: [String]
}

/// This suite proves AppSentinel's degraded (`eslogger`-unavailable)
/// polling path is not merely detected but functionally protective: it
/// exercises every kind of change PollingEventSource is responsible for
/// finding, using fully synthetic adapters so no part of the real Mac is
/// touched.
final class PollingEventSourceTests: XCTestCase {
    var tempDir: URL!

    override func setUpWithError() throws {
        tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir.appendingPathComponent(".ssh"), withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: tempDir)
    }

    func testDetectsNewlyDiscoveredDescendantProcess() throws {
        let root = ProcessID(1)
        let tree = ProcessTreeTracker(rootPID: root)
        let processListing = FakeProcessListing(processes: [
            ProcessSnapshot(pid: root, parentPID: ProcessID(0), executablePath: "/root")
        ])
        let certs = FakeCertificateSnapshotting(certificates: [])
        let network = FakeNetworkStateSnapshotting(state: NetworkState())
        let paths = FakeSensitivePathProviding(homeDirectory: tempDir.path, watchedDirectories: [])

        let source = PollingEventSource(tree: tree, processListing: processListing, certificateSnapshotting: certs, networkStateSnapshotting: network, sensitivePathProviding: paths, pollInterval: 0.1)

        var events: [SecurityEvent] = []
        let lock = NSLock()
        try source.start { event in lock.lock(); events.append(event); lock.unlock() }
        defer { source.stop() }

        Thread.sleep(forTimeInterval: 0.15)
        processListing.lock.lock()
        processListing.processes.append(ProcessSnapshot(pid: ProcessID(2), parentPID: root, executablePath: "/bin/bash"))
        processListing.lock.unlock()

        let deadline = Date().addingTimeInterval(2)
        while Date() < deadline {
            lock.lock(); let found = events.contains { $0.pid == ProcessID(2) }; lock.unlock()
            if found { break }
            Thread.sleep(forTimeInterval: 0.05)
        }

        lock.lock(); defer { lock.unlock() }
        XCTAssertTrue(events.contains { event in
            guard event.pid == ProcessID(2), case .processExec(let path, _, _) = event.kind else { return false }
            return path == "/bin/bash"
        })
        XCTAssertTrue(tree.contains(ProcessID(2)))
    }

    func testDetectsNewlyAddedCertificate() throws {
        let root = ProcessID(1)
        let tree = ProcessTreeTracker(rootPID: root)
        let processListing = FakeProcessListing(processes: [ProcessSnapshot(pid: root, parentPID: ProcessID(0), executablePath: "/root")])
        let certs = FakeCertificateSnapshotting(certificates: [])
        let network = FakeNetworkStateSnapshotting(state: NetworkState())
        let paths = FakeSensitivePathProviding(homeDirectory: tempDir.path, watchedDirectories: [])

        let source = PollingEventSource(tree: tree, processListing: processListing, certificateSnapshotting: certs, networkStateSnapshotting: network, sensitivePathProviding: paths, pollInterval: 0.1)
        var events: [SecurityEvent] = []
        let lock = NSLock()
        try source.start { event in lock.lock(); events.append(event); lock.unlock() }
        defer { source.stop() }

        Thread.sleep(forTimeInterval: 0.15)
        certs.lock.lock()
        certs.certificates.append(CertificateRecord(sha1Fingerprint: "NEW", subject: "CN=new", keychainPath: "/k"))
        certs.lock.unlock()

        let deadline = Date().addingTimeInterval(2)
        while Date() < deadline {
            lock.lock()
            let found = events.contains { if case .certificateAdded = $0.kind { return true }; return false }
            lock.unlock()
            if found { break }
            Thread.sleep(forTimeInterval: 0.05)
        }

        lock.lock(); defer { lock.unlock() }
        XCTAssertTrue(events.contains { if case .certificateAdded(let cert) = $0.kind { return cert.sha1Fingerprint == "NEW" }; return false })
    }

    func testDetectsNetworkProxyChange() throws {
        let root = ProcessID(1)
        let tree = ProcessTreeTracker(rootPID: root)
        let processListing = FakeProcessListing(processes: [ProcessSnapshot(pid: root, parentPID: ProcessID(0), executablePath: "/root")])
        let certs = FakeCertificateSnapshotting(certificates: [])
        let network = FakeNetworkStateSnapshotting(state: NetworkState(httpProxy: nil))
        let paths = FakeSensitivePathProviding(homeDirectory: tempDir.path, watchedDirectories: [])

        let source = PollingEventSource(tree: tree, processListing: processListing, certificateSnapshotting: certs, networkStateSnapshotting: network, sensitivePathProviding: paths, pollInterval: 0.1)
        var events: [SecurityEvent] = []
        let lock = NSLock()
        try source.start { event in lock.lock(); events.append(event); lock.unlock() }
        defer { source.stop() }

        Thread.sleep(forTimeInterval: 0.15)
        network.lock.lock()
        network.state.httpProxy = "10.0.0.1:8080"
        network.lock.unlock()

        let deadline = Date().addingTimeInterval(2)
        while Date() < deadline {
            lock.lock()
            let found = events.contains { if case .networkStateChanged = $0.kind { return true }; return false }
            lock.unlock()
            if found { break }
            Thread.sleep(forTimeInterval: 0.05)
        }

        lock.lock(); defer { lock.unlock() }
        XCTAssertTrue(events.contains { if case .networkStateChanged(_, let after) = $0.kind { return after.httpProxy == "10.0.0.1:8080" }; return false })
    }

    func testDetectsNewFileInWatchedSensitiveDirectory() throws {
        let root = ProcessID(1)
        let tree = ProcessTreeTracker(rootPID: root)
        let processListing = FakeProcessListing(processes: [ProcessSnapshot(pid: root, parentPID: ProcessID(0), executablePath: "/root")])
        let certs = FakeCertificateSnapshotting(certificates: [])
        let network = FakeNetworkStateSnapshotting(state: NetworkState())
        let sshDir = tempDir.appendingPathComponent(".ssh")
        let paths = FakeSensitivePathProviding(homeDirectory: tempDir.path, watchedDirectories: [sshDir.path])

        let source = PollingEventSource(tree: tree, processListing: processListing, certificateSnapshotting: certs, networkStateSnapshotting: network, sensitivePathProviding: paths, pollInterval: 0.1)
        var events: [SecurityEvent] = []
        let lock = NSLock()
        try source.start { event in lock.lock(); events.append(event); lock.unlock() }
        defer { source.stop() }

        Thread.sleep(forTimeInterval: 0.15)
        let newKeyPath = sshDir.appendingPathComponent("id_ed25519")
        try "fake-key-material".write(to: newKeyPath, atomically: true, encoding: .utf8)

        let deadline = Date().addingTimeInterval(2)
        while Date() < deadline {
            lock.lock()
            let found = events.contains { if case .sensitivePathWrite = $0.kind { return true }; return false }
            lock.unlock()
            if found { break }
            Thread.sleep(forTimeInterval: 0.05)
        }

        lock.lock(); defer { lock.unlock() }
        XCTAssertTrue(events.contains { event in
            guard case .sensitivePathWrite(let path, let category) = event.kind else { return false }
            return path == newKeyPath.path && category == .sshPrivateKey
        })
    }
}
