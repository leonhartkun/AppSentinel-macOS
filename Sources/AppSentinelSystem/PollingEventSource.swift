import Foundation
import AppSentinelCore

/// The independent-verification / degraded-mode monitoring path: on a
/// fixed interval, re-lists processes, re-snapshots certificates, network
/// state, and watched directories, and emits `SecurityEvent`s for whatever
/// changed. Always available (no special privileges required), so it runs
/// for every session regardless of whether `eslogger` is also active, and
/// becomes the *only* detection path when `eslogger` is unavailable.
///
/// Polling has an inherent limitation `eslogger` does not: it can observe
/// that a protected file was created or modified, but — unlike a live
/// open-event stream — it cannot reliably attribute *which* process did it,
/// nor can it observe a plain *read* at all (a read never changes a file's
/// modification time). Protected-path reads are therefore only detected
/// when `eslogger` is available; this is surfaced to the user, not hidden.
public final class PollingEventSource: SecurityEventSource {
    public let tree: ProcessTreeTracker
    private let processListing: ProcessListing
    private let certificateSnapshotting: CertificateSnapshotting
    private let networkStateSnapshotting: NetworkStateSnapshotting
    private let sensitivePathProviding: SensitivePathProviding
    private let directoryScanner: DirectoryScanner
    private let classifier: SensitivePathClassifier
    private let pollInterval: TimeInterval

    private var timer: DispatchSourceTimer?
    private let queue = DispatchQueue(label: "com.appsentinel.polling")

    private var previousCertificates: [CertificateRecord] = []
    private var previousNetworkState: NetworkState?
    private var previousDirectorySnapshot: DirectorySnapshot = .empty

    public init(
        tree: ProcessTreeTracker,
        processListing: ProcessListing,
        certificateSnapshotting: CertificateSnapshotting,
        networkStateSnapshotting: NetworkStateSnapshotting,
        sensitivePathProviding: SensitivePathProviding,
        directoryScanner: DirectoryScanner = DirectoryScanner(),
        pollInterval: TimeInterval = 1.0
    ) {
        self.tree = tree
        self.processListing = processListing
        self.certificateSnapshotting = certificateSnapshotting
        self.networkStateSnapshotting = networkStateSnapshotting
        self.sensitivePathProviding = sensitivePathProviding
        self.directoryScanner = directoryScanner
        self.classifier = SensitivePathClassifier(homeDirectory: sensitivePathProviding.homeDirectory)
        self.pollInterval = pollInterval
    }

    public func start(onEvent: @escaping (SecurityEvent) -> Void) throws {
        // Establish the launch-time baseline synchronously so the first
        // tick reports only real changes, not "everything that already
        // existed before we started watching."
        captureBaseline()

        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + pollInterval, repeating: pollInterval)
        timer.setEventHandler { [weak self] in
            self?.tick(onEvent: onEvent)
        }
        timer.resume()
        self.timer = timer
    }

    public func stop() {
        timer?.cancel()
        timer = nil
    }

    private func captureBaseline() {
        previousCertificates = (try? certificateSnapshotting.snapshot()) ?? []
        previousNetworkState = try? networkStateSnapshotting.snapshot()
        previousDirectorySnapshot = directoryScanner.scan(directories: sensitivePathProviding.watchedDirectories)
    }

    private func tick(onEvent: @escaping (SecurityEvent) -> Void) {
        let now = Date()

        if let processes = try? processListing.currentProcesses() {
            let byPID = Dictionary(uniqueKeysWithValues: processes.map { ($0.pid, $0) })
            let newlyDiscovered = tree.absorb(systemProcesses: processes)
            for pid in newlyDiscovered {
                let path = byPID[pid]?.executablePath ?? ""
                onEvent(SecurityEvent(pid: pid, timestamp: now, kind: .processExec(path: path, arguments: [], sha256: nil)))
            }
        }

        if let certificates = try? certificateSnapshotting.snapshot() {
            let diff = StateSnapshotDiff.diffCertificates(before: previousCertificates, after: certificates)
            for added in diff.added {
                onEvent(SecurityEvent(pid: tree.rootPID, timestamp: now, kind: .certificateAdded(added)))
            }
            for removed in diff.removed {
                onEvent(SecurityEvent(pid: tree.rootPID, timestamp: now, kind: .certificateRemoved(removed)))
            }
            previousCertificates = certificates
        }

        if let network = try? networkStateSnapshotting.snapshot() {
            if let previous = previousNetworkState, previous != network {
                onEvent(SecurityEvent(pid: tree.rootPID, timestamp: now, kind: .networkStateChanged(before: previous, after: network)))
            }
            previousNetworkState = network
        }

        let directorySnapshot = directoryScanner.scan(directories: sensitivePathProviding.watchedDirectories)
        let changes = StateSnapshotDiff.diff(before: previousDirectorySnapshot, after: directorySnapshot)
        for change in changes where change.kind != .removed {
            guard let category = classifier.classify(change.path) else { continue }
            onEvent(SecurityEvent(pid: tree.rootPID, timestamp: now, kind: .sensitivePathWrite(path: change.path, category: category)))
        }
        previousDirectorySnapshot = directorySnapshot
    }
}
