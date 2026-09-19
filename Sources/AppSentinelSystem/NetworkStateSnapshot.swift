import Foundation
import AppSentinelCore

/// Reads network configuration via `scutil` and `route`, and restores only
/// the HTTP/HTTPS proxy fields (via `networksetup`) on a critical
/// violation. DNS and routing are reported, never silently rewritten —
/// AppSentinel cannot always know which change is safe to reverse, and the
/// design explicitly limits automatic recovery to what it can undo without
/// risking an unrelated interface.
public struct RealNetworkStateSnapshot: NetworkStateSnapshotting {
    public init() {}

    public func snapshot() throws -> NetworkState {
        let proxyOutput = (try? ShellRunner.run("/usr/sbin/scutil", arguments: ["--proxy"])) ?? ""
        let (http, https) = Self.parseProxy(proxyOutput)

        let dnsOutput = (try? ShellRunner.run("/usr/sbin/scutil", arguments: ["--dns"])) ?? ""
        let dns = Self.parsePrimaryDNS(dnsOutput)

        let routeOutput = (try? ShellRunner.run("/sbin/route", arguments: ["-n", "get", "default"])) ?? ""
        let gateway = Self.parseGateway(routeOutput)

        return NetworkState(httpProxy: http, httpsProxy: https, dnsServers: dns, defaultRouteGateway: gateway)
    }

    public func restoreProxy(from state: NetworkState) throws {
        guard let service = try Self.primaryNetworkServiceName() else { return }

        if let http = state.httpProxy, let (host, port) = Self.splitHostPort(http) {
            try ShellRunner.run("/usr/sbin/networksetup", arguments: ["-setwebproxy", service, host, port])
            try ShellRunner.run("/usr/sbin/networksetup", arguments: ["-setwebproxystate", service, "on"])
        } else {
            try ShellRunner.run("/usr/sbin/networksetup", arguments: ["-setwebproxystate", service, "off"])
        }

        if let https = state.httpsProxy, let (host, port) = Self.splitHostPort(https) {
            try ShellRunner.run("/usr/sbin/networksetup", arguments: ["-setsecurewebproxy", service, host, port])
            try ShellRunner.run("/usr/sbin/networksetup", arguments: ["-setsecurewebproxystate", service, "on"])
        } else {
            try ShellRunner.run("/usr/sbin/networksetup", arguments: ["-setsecurewebproxystate", service, "off"])
        }
    }

    // MARK: - Parsing

    static func parseProxy(_ output: String) -> (http: String?, https: String?) {
        var httpEnabled = false, httpsEnabled = false
        var httpHost: String?, httpPort: String?
        var httpsHost: String?, httpsPort: String?

        for rawLine in output.split(separator: "\n") {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            let parts = line.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            guard parts.count == 2 else { continue }
            switch parts[0] {
            case "HTTPEnable": httpEnabled = parts[1] == "1"
            case "HTTPProxy": httpHost = parts[1]
            case "HTTPPort": httpPort = parts[1]
            case "HTTPSEnable": httpsEnabled = parts[1] == "1"
            case "HTTPSProxy": httpsHost = parts[1]
            case "HTTPSPort": httpsPort = parts[1]
            default: break
            }
        }

        let http: String? = (httpEnabled && httpHost != nil) ? "\(httpHost!):\(httpPort ?? "0")" : nil
        let https: String? = (httpsEnabled && httpsHost != nil) ? "\(httpsHost!):\(httpsPort ?? "0")" : nil
        return (http, https)
    }

    static func parsePrimaryDNS(_ output: String) -> [String] {
        var servers: [String] = []
        var inFirstResolver = false
        for rawLine in output.split(separator: "\n") {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("resolver #1") {
                inFirstResolver = true
                continue
            }
            if line.hasPrefix("resolver #") {
                inFirstResolver = false
                continue
            }
            guard inFirstResolver, line.hasPrefix("nameserver[") else { continue }
            if let colonIndex = line.firstIndex(of: ":") {
                let value = line[line.index(after: colonIndex)...].trimmingCharacters(in: .whitespaces)
                servers.append(value)
            }
        }
        return servers
    }

    static func parseGateway(_ output: String) -> String? {
        for rawLine in output.split(separator: "\n") {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("gateway:") {
                return line.replacingOccurrences(of: "gateway:", with: "").trimmingCharacters(in: .whitespaces)
            }
        }
        return nil
    }

    static func parseDefaultInterface(_ output: String) -> String? {
        for rawLine in output.split(separator: "\n") {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("interface:") {
                return line.replacingOccurrences(of: "interface:", with: "").trimmingCharacters(in: .whitespaces)
            }
        }
        return nil
    }

    static func splitHostPort(_ value: String) -> (String, String)? {
        guard let colonIndex = value.lastIndex(of: ":") else { return nil }
        let host = String(value[value.startIndex..<colonIndex])
        let port = String(value[value.index(after: colonIndex)...])
        guard !host.isEmpty, !port.isEmpty else { return nil }
        return (host, port)
    }

    static func primaryNetworkServiceName() throws -> String? {
        let routeOutput = try ShellRunner.run("/sbin/route", arguments: ["-n", "get", "default"])
        guard let interface = parseDefaultInterface(routeOutput) else { return nil }

        let hardwareOutput = try ShellRunner.run("/usr/sbin/networksetup", arguments: ["-listallhardwareports"])
        return matchHardwarePort(forDevice: interface, in: hardwareOutput)
    }

    static func matchHardwarePort(forDevice interface: String, in hardwareListing: String) -> String? {
        var currentPort: String?
        for rawLine in hardwareListing.split(separator: "\n") {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("Hardware Port:") {
                currentPort = line.replacingOccurrences(of: "Hardware Port:", with: "").trimmingCharacters(in: .whitespaces)
            } else if line.hasPrefix("Device:") {
                let device = line.replacingOccurrences(of: "Device:", with: "").trimmingCharacters(in: .whitespaces)
                if device == interface {
                    return currentPort
                }
            }
        }
        return nil
    }
}
