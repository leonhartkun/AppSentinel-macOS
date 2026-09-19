import XCTest
@testable import AppSentinelCore

final class NetworkPolicyTests: XCTestCase {
    func testAllowedProxyChangeIsPermitted() {
        var enrollment: CertificateEnrollmentWindow? = nil
        var policy = SecurityPolicy.empty
        policy.allowedNetworkChanges.append(NetworkRule(field: .httpProxy, allowedValue: "127.0.0.1:8080"))

        let before = NetworkState(httpProxy: nil, httpsProxy: nil, dnsServers: ["8.8.8.8"], defaultRouteGateway: "192.168.1.1")
        let after = NetworkState(httpProxy: "127.0.0.1:8080", httpsProxy: nil, dnsServers: ["8.8.8.8"], defaultRouteGateway: "192.168.1.1")

        let event = SecurityEvent(pid: ProcessID(1), timestamp: Date(), kind: .networkStateChanged(before: before, after: after))
        let decision = PolicyEvaluator.evaluate(event, policy: policy, enrollment: &enrollment)

        XCTAssertEqual(decision, .allow)
    }

    func testProxyChangeToUndeclaredValueIsCritical() {
        var enrollment: CertificateEnrollmentWindow? = nil
        var policy = SecurityPolicy.empty
        policy.allowedNetworkChanges.append(NetworkRule(field: .httpProxy, allowedValue: "127.0.0.1:8080"))

        let before = NetworkState(httpProxy: nil, httpsProxy: nil, dnsServers: [], defaultRouteGateway: nil)
        let after = NetworkState(httpProxy: "203.0.113.9:3128", httpsProxy: nil, dnsServers: [], defaultRouteGateway: nil)

        let event = SecurityEvent(pid: ProcessID(1), timestamp: Date(), kind: .networkStateChanged(before: before, after: after))
        let decision = PolicyEvaluator.evaluate(event, policy: policy, enrollment: &enrollment)

        guard case .critical = decision else {
            return XCTFail("expected critical decision, got \(decision)")
        }
    }

    func testDNSChangeOutsidePolicyIsCritical() {
        var enrollment: CertificateEnrollmentWindow? = nil
        let before = NetworkState(dnsServers: ["8.8.8.8"])
        let after = NetworkState(dnsServers: ["45.33.32.156"])

        let event = SecurityEvent(pid: ProcessID(1), timestamp: Date(), kind: .networkStateChanged(before: before, after: after))
        let decision = PolicyEvaluator.evaluate(event, policy: .empty, enrollment: &enrollment)

        guard case .critical(let reason) = decision else {
            return XCTFail("expected critical decision, got \(decision)")
        }
        XCTAssertTrue(reason.contains("DNS"))
    }

    func testRouteChangeWithWildcardAllowanceIsPermitted() {
        var enrollment: CertificateEnrollmentWindow? = nil
        var policy = SecurityPolicy.empty
        policy.allowedNetworkChanges.append(NetworkRule(field: .defaultRoute, allowedValue: nil))

        let before = NetworkState(defaultRouteGateway: "192.168.1.1")
        let after = NetworkState(defaultRouteGateway: "192.168.1.254")

        let event = SecurityEvent(pid: ProcessID(1), timestamp: Date(), kind: .networkStateChanged(before: before, after: after))
        let decision = PolicyEvaluator.evaluate(event, policy: policy, enrollment: &enrollment)

        XCTAssertEqual(decision, .allow)
    }

    func testNoChangeAtAllIsAllowed() {
        var enrollment: CertificateEnrollmentWindow? = nil
        let state = NetworkState(httpProxy: "same", httpsProxy: "same", dnsServers: ["1.1.1.1"], defaultRouteGateway: "10.0.0.1")

        let event = SecurityEvent(pid: ProcessID(1), timestamp: Date(), kind: .networkStateChanged(before: state, after: state))
        let decision = PolicyEvaluator.evaluate(event, policy: .empty, enrollment: &enrollment)

        XCTAssertEqual(decision, .allow)
    }
}
