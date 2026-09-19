import Foundation

/// The outcome of evaluating one security event against the active policy.
public enum Decision: Sendable, Equatable {
    case allow
    /// A critical policy violation. `reason` is a human-readable (Chinese)
    /// explanation suitable for both the terminal and the evidence log.
    case critical(reason: String)
}

/// Pure policy evaluation: given an event, the declared policy, and mutable
/// certificate-enrollment state, decide whether the event is allowed or a
/// critical violation. Contains no I/O — entirely testable with synthetic
/// events.
public enum PolicyEvaluator {
    public static func evaluate(
        _ event: SecurityEvent,
        policy: SecurityPolicy,
        enrollment: inout CertificateEnrollmentWindow?
    ) -> Decision {
        switch event.kind {
        case .processExec(let path, _, _):
            return evaluateExec(path: path, policy: policy)

        case .processFork, .processExit:
            return .allow

        case .sensitivePathRead(let path, let category):
            return evaluateSensitivePathAccess(path: path, category: category, policy: policy, verb: "读取")

        case .sensitivePathWrite(let path, let category):
            return evaluateSensitivePathAccess(path: path, category: category, policy: policy, verb: "修改")

        case .executableDropped(let path, _):
            if policy.allowedScriptPaths.contains(path) {
                return .allow
            }
            return .critical(reason: "检测到未经授权释放的新可执行文件：\(path)")

        case .certificateAdded(let cert):
            return evaluateCertificateAdded(cert, at: event.timestamp, enrollment: &enrollment)

        case .certificateRemoved(let cert):
            return .critical(reason: "检测到证书被删除，超出登记窗口范围：\(cert.subject)")

        case .certificateTrustChanged(let cert):
            return .critical(reason: "检测到证书信任设置变化，超出登记窗口范围：\(cert.subject)")

        case .networkStateChanged(let before, let after):
            return evaluateNetworkChange(before: before, after: after, policy: policy)
        }
    }

    private static func evaluateExec(path: String, policy: SecurityPolicy) -> Decision {
        if ShellInterpreters.isShellLike(path) {
            if policy.allowedShellExecutables.contains(path) {
                return .allow
            }
            return .critical(reason: "检测到未经授权的 shell 或脚本解释器启动：\(path)")
        }
        return .allow
    }

    private static func evaluateSensitivePathAccess(
        path: String,
        category: SensitivePathCategory,
        policy: SecurityPolicy,
        verb: String
    ) -> Decision {
        if policy.protectedPathExceptions.contains(path) {
            return .allow
        }
        let categoryDescription: String
        switch category {
        case .sshPrivateKey: categoryDescription = "SSH 密钥"
        case .browserCredentialStore: categoryDescription = "浏览器凭据数据库"
        case .keychainFile: categoryDescription = "钥匙串文件"
        case .launchPersistence: categoryDescription = "LaunchAgent/LaunchDaemon 持久化位置"
        case .loginItem: categoryDescription = "登录项"
        case .systemExtension: categoryDescription = "系统扩展"
        case .other: categoryDescription = "受保护路径"
        }
        return .critical(reason: "检测到未经授权\(verb)受保护路径（\(categoryDescription)）：\(path)")
    }

    private static func evaluateCertificateAdded(
        _ cert: CertificateRecord,
        at date: Date,
        enrollment: inout CertificateEnrollmentWindow?
    ) -> Decision {
        guard enrollment != nil else {
            return .critical(reason: "检测到新增证书，但当前会话未开启证书登记窗口：\(cert.subject)")
        }
        switch enrollment!.evaluate(at: date) {
        case .permitted:
            return .allow
        case .violatesSecondCertificate:
            return .critical(reason: "登记窗口内已登记过一张证书，检测到第二张新增证书：\(cert.subject)")
        case .violatesOutsideWindow:
            return .critical(reason: "检测到证书新增发生在登记窗口之外：\(cert.subject)")
        }
    }

    private static func evaluateNetworkChange(
        before: NetworkState,
        after: NetworkState,
        policy: SecurityPolicy
    ) -> Decision {
        var violations: [String] = []

        func isAllowed(_ field: NetworkRule.Field, newValue: String?) -> Bool {
            policy.allowedNetworkChanges.contains { rule in
                guard rule.field == field else { return false }
                guard let allowedValue = rule.allowedValue else { return true }
                return allowedValue == newValue
            }
        }

        if before.httpProxy != after.httpProxy, !isAllowed(.httpProxy, newValue: after.httpProxy) {
            violations.append("HTTP 代理由 \(before.httpProxy ?? "无") 变为 \(after.httpProxy ?? "无")")
        }
        if before.httpsProxy != after.httpsProxy, !isAllowed(.httpsProxy, newValue: after.httpsProxy) {
            violations.append("HTTPS 代理由 \(before.httpsProxy ?? "无") 变为 \(after.httpsProxy ?? "无")")
        }
        if before.dnsServers != after.dnsServers, !isAllowed(.dns, newValue: after.dnsServers.joined(separator: ",")) {
            violations.append("DNS 服务器由 \(before.dnsServers) 变为 \(after.dnsServers)")
        }
        if before.defaultRouteGateway != after.defaultRouteGateway,
           !isAllowed(.defaultRoute, newValue: after.defaultRouteGateway) {
            violations.append("默认路由网关由 \(before.defaultRouteGateway ?? "无") 变为 \(after.defaultRouteGateway ?? "无")")
        }

        if violations.isEmpty {
            return .allow
        }
        return .critical(reason: "检测到策略之外的网络状态变化：" + violations.joined(separator: "；"))
    }
}
