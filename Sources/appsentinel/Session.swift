import Foundation
import AppSentinelCore
import AppSentinelSystem

/// The system adapters a `Session` depends on. Production code uses
/// `.production`, which wires up the real system; integration tests inject
/// a value with a temporary-directory-backed `SensitivePathProviding` and
/// fully synthetic certificate/network adapters, so exercising a real
/// critical-violation-and-recovery flow never touches an actual keychain,
/// system proxy, or launch-item directory.
struct SessionDependencies {
    var processListing: ProcessListing
    var terminator: ProcessTerminating
    var hasher: ExecutableHashing
    var certificateSnapshotting: CertificateSnapshotting
    var networkStateSnapshotting: NetworkStateSnapshotting
    var sensitivePathProviding: SensitivePathProviding

    static let production = SessionDependencies(
        processListing: RealProcessLister(),
        terminator: RealProcessTerminator(),
        hasher: RealExecutableHasher(),
        certificateSnapshotting: RealCertificateSnapshot(),
        networkStateSnapshotting: RealNetworkStateSnapshot(),
        sensitivePathProviding: RealSensitivePathProvider()
    )
}

/// Orchestrates one `appsentinel run` invocation end to end: resolves and
/// launches the target, starts the eslogger/polling event sources, applies
/// policy to every observed event, and responds to a critical violation by
/// terminating the monitored tree and restoring what it safely can.
final class Session {
    let options: RunOptions
    let output = TerminalOutput()

    private let processListing: ProcessListing
    private let terminator: ProcessTerminating
    private let hasher: ExecutableHashing
    private let certificateSnapshotting: CertificateSnapshotting
    private let networkStateSnapshotting: NetworkStateSnapshotting
    private let sensitivePathProviding: SensitivePathProviding

    private var policy: SecurityPolicy = .empty
    private var enrollmentWindow: CertificateEnrollmentWindow?
    private var tree: ProcessTreeTracker!
    private var evidenceLogger: EvidenceLogger!
    private var sessionID = ""
    private var launchNetworkState: NetworkState?

    private var pollingSource: PollingEventSource?
    private var esLoggerSource: ESLoggerEventSource?
    private var livenessTimer: DispatchSourceTimer?

    private let completionSemaphore = DispatchSemaphore(value: 0)
    private var exitCode: Int32 = 0
    private var hasTriggeredCriticalResponse = false
    private let stateQueue = DispatchQueue(label: "com.appsentinel.session")

    init(options: RunOptions, dependencies: SessionDependencies = .production) {
        self.options = options
        self.processListing = dependencies.processListing
        self.terminator = dependencies.terminator
        self.hasher = dependencies.hasher
        self.certificateSnapshotting = dependencies.certificateSnapshotting
        self.networkStateSnapshotting = dependencies.networkStateSnapshotting
        self.sensitivePathProviding = dependencies.sensitivePathProviding
    }

    func run() -> Int32 {
        do {
            try execute()
        } catch {
            output.critical("\(error)")
            return 1
        }
        completionSemaphore.wait()
        return exitCode
    }

    private func execute() throws {
        let launcher = AppLauncher()
        let executablePath = try launcher.resolveExecutable(appBundlePath: options.appBundlePath)

        policy = try buildPolicy()

        sessionID = Self.makeSessionID()
        let sessionDirectory = try resolveSessionDirectory()
        evidenceLogger = try EvidenceLogger(sessionDirectory: sessionDirectory)
        output.info("证据日志目录：\(sessionDirectory.path)")

        if let window = options.certificateEnrollmentDuration {
            enrollmentWindow = CertificateEnrollmentWindow(start: Date(), duration: window)
            output.info("已开启证书登记窗口，时长 \(Int(window)) 秒，窗口内最多允许一张新增证书。")
        }

        launchNetworkState = try? networkStateSnapshotting.snapshot()

        let availability = options.forcePolling
            ? ESLoggerAvailability(isAvailable: false, reason: "已通过 --no-eslogger 强制使用轮询模式")
            : ESLoggerAvailabilityProbe.probe()

        if availability.isAvailable {
            output.success("eslogger 可用，进入近实时监控模式。")
        } else {
            output.warning("eslogger 不可用（\(availability.reason ?? "未知原因")），已进入轮询降级模式。")
            output.warning("降级模式下检测存在延迟，且无法感知受保护路径的读取行为，保护能力低于近实时模式。")
        }

        output.info("正在启动目标应用：\(executablePath)")
        let launched = try launcher.launch(executablePath: executablePath)
        output.success("目标已启动，根进程 PID：\(launched.pid)")

        tree = ProcessTreeTracker(rootPID: launched.pid)
        try? evidenceLogger.writeSessionSummary([
            "sessionID": sessionID,
            "target": options.appBundlePath,
            "executable": executablePath,
            "rootPID": String(launched.pid.rawValue),
            "eslogger": availability.isAvailable ? "available" : "degraded-polling"
        ])

        let polling = PollingEventSource(
            tree: tree,
            processListing: processListing,
            certificateSnapshotting: certificateSnapshotting,
            networkStateSnapshotting: networkStateSnapshotting,
            sensitivePathProviding: sensitivePathProviding
        )
        self.pollingSource = polling
        try polling.start { [weak self] event in
            self?.stateQueue.async { self?.handle(event) }
        }

        if availability.isAvailable {
            let classifier = SensitivePathClassifier(homeDirectory: sensitivePathProviding.homeDirectory)
            let esSource = ESLoggerEventSource(sensitiveClassifier: classifier)
            self.esLoggerSource = esSource
            do {
                try esSource.start { [weak self] event in
                    self?.stateQueue.async { self?.handle(event) }
                }
            } catch {
                output.warning("eslogger 启动失败，继续依赖轮询模式：\(error.localizedDescription)")
            }
        }

        startLivenessMonitoring()
        output.info("正在监控目标进程树，等待其退出或触发策略响应……")
    }

    private func buildPolicy() throws -> SecurityPolicy {
        var filePolicy = SecurityPolicy.empty
        if let policyPath = options.policyFilePath {
            let data = try Data(contentsOf: URL(fileURLWithPath: policyPath))
            filePolicy = try PolicyFile.decode(data)
            output.info("已加载策略文件：\(policyPath)")
        }

        var cliPolicy = SecurityPolicy.empty
        cliPolicy.allowedShellExecutables = Set(options.allowedShellExecutables)
        cliPolicy.allowedScriptPaths = Set(options.allowedScriptPaths)
        cliPolicy.protectedPathExceptions = Set(options.protectedPathExceptions)
        cliPolicy.certificateEnrollmentWindow = options.certificateEnrollmentDuration

        return filePolicy.merging(cliPolicy)
    }

    private func resolveSessionDirectory() throws -> URL {
        let base: URL
        if let logDir = options.logDirectory {
            base = URL(fileURLWithPath: logDir)
        } else {
            base = FileManager.default.homeDirectoryForCurrentUser
                .appendingPathComponent("Library/Logs/AppSentinel", isDirectory: true)
        }
        return base.appendingPathComponent(sessionID, isDirectory: true)
    }

    private static func makeSessionID() -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyyMMdd-HHmmss"
        formatter.timeZone = TimeZone.current
        let suffix = UUID().uuidString.prefix(6)
        return "\(formatter.string(from: Date()))-\(suffix)"
    }

    // MARK: - Event handling (always invoked serially on stateQueue)

    private func handle(_ event: SecurityEvent) {
        guard !hasTriggeredCriticalResponse else { return }

        switch event.kind {
        case .processFork(let childPID):
            guard tree.contains(event.pid) else { return }
            tree.recordChild(childPID, parentPID: event.pid, executablePath: nil)
            return
        case .processExit:
            return
        default:
            break
        }

        guard tree.contains(event.pid) else { return }

        let decision = PolicyEvaluator.evaluate(event, policy: policy, enrollment: &enrollmentWindow)
        logEvidence(event: event, decision: decision)

        if case .critical(let reason) = decision {
            respondToCriticalViolation(reason: reason, event: event)
        }
    }

    private func logEvidence(event: SecurityEvent, decision: Decision) {
        let description = Self.describe(event.kind)
        let decisionText: String
        if case .critical = decision { decisionText = "critical" } else { decisionText = "allow" }
        try? evidenceLogger.appendEvent(EvidenceEvent(
            timestamp: event.timestamp,
            pid: event.pid.rawValue,
            description: description,
            decision: decisionText
        ))
    }

    private static func describe(_ kind: SecurityEventKind) -> String {
        switch kind {
        case .processExec(let path, _, _): return "执行：\(path)"
        case .processFork: return "创建子进程"
        case .processExit: return "进程退出"
        case .sensitivePathRead(let path, _): return "读取受保护路径：\(path)"
        case .sensitivePathWrite(let path, _): return "修改受保护路径：\(path)"
        case .executableDropped(let path, _): return "释放新可执行文件：\(path)"
        case .certificateAdded(let cert): return "新增证书：\(cert.subject)"
        case .certificateRemoved(let cert): return "删除证书：\(cert.subject)"
        case .certificateTrustChanged(let cert): return "证书信任变化：\(cert.subject)"
        case .networkStateChanged: return "网络状态变化"
        }
    }

    private func respondToCriticalViolation(reason: String, event: SecurityEvent) {
        hasTriggeredCriticalResponse = true
        output.critical("检测到严重策略违规：\(reason)")

        let ancestry = tree.ancestry(of: event.pid).map { entry -> AncestryEntry in
            let hash = entry.executablePath.flatMap { hasher.sha256(ofFileAt: $0) }
            return AncestryEntry(pid: entry.pid, executablePath: entry.executablePath, sha256: hash)
        }

        try? evidenceLogger.writeViolation(ViolationEvidence(
            sessionID: sessionID,
            timestamp: Date(),
            triggeringReason: reason,
            ancestry: ancestry,
            stateDiffLines: []
        ))

        let plan = ResponsePlan.forCriticalViolation(reason: reason, tree: tree)
        output.info("正在终止受监控进程树（先终止子进程，再终止根进程）……")
        for pid in plan.terminationOrder {
            try? terminator.terminate(pid, signal: SIGTERM)
        }
        Thread.sleep(forTimeInterval: 0.3)
        for pid in plan.terminationOrder where terminator.isAlive(pid) {
            try? terminator.terminate(pid, signal: SIGKILL)
        }
        output.success("受监控进程树已终止。")

        if plan.shouldRestoreNetworkState, let baseline = launchNetworkState {
            do {
                try networkStateSnapshotting.restoreProxy(from: baseline)
                output.success("已尝试恢复启动前的系统代理设置。")
            } catch {
                output.warning("恢复系统代理设置失败，请手动检查：\(error.localizedDescription)")
            }
        }
        output.warning("证书、启动项等无法安全自动撤销的变化不会被自动删除，请查看证据日志后手动处理。")

        finish(exitCode: 2)
    }

    // MARK: - Liveness monitoring / normal exit

    private func startLivenessMonitoring() {
        let timer = DispatchSource.makeTimerSource(queue: stateQueue)
        timer.schedule(deadline: .now() + 1.0, repeating: 1.0)
        timer.setEventHandler { [weak self] in
            self?.checkLiveness()
        }
        timer.resume()
        livenessTimer = timer
    }

    private func checkLiveness() {
        guard !hasTriggeredCriticalResponse else { return }
        let pids = tree.trackedPIDs
        let anyAlive = pids.contains { terminator.isAlive($0) }
        if !anyAlive {
            output.success("目标应用及其全部子进程已正常退出，监控器同步退出。")
            finish(exitCode: 0)
        }
    }

    private func finish(exitCode: Int32) {
        pollingSource?.stop()
        esLoggerSource?.stop()
        livenessTimer?.cancel()
        livenessTimer = nil
        self.exitCode = exitCode
        completionSemaphore.signal()
    }
}
