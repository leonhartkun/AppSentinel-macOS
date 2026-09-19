import XCTest
@testable import AppSentinelSystem

final class NetworkStateSnapshotParsingTests: XCTestCase {
    // Captured verbatim from real `scutil --proxy` output on the
    // development machine (no proxy configured).
    static let proxyDisabledOutput = """
    <dictionary> {
      ExceptionsList : <array> {
        0 : 127.0.0.1
        1 : localhost
      }
      FTPPassive : 1
      HTTPEnable : 0
      HTTPSEnable : 0
      SOCKSEnable : 0
    }
    """

    static let proxyEnabledOutput = """
    <dictionary> {
      HTTPEnable : 1
      HTTPPort : 8080
      HTTPProxy : 127.0.0.1
      HTTPSEnable : 1
      HTTPSPort : 8080
      HTTPSProxy : 127.0.0.1
    }
    """

    // Captured verbatim from real `scutil --dns` output.
    static let dnsOutput = """
    DNS configuration

    resolver #1
      search domain[0] : fritz.box
      nameserver[0] : 1.1.1.1
      nameserver[1] : 8.8.8.8
      flags    : Request A records, Request AAAA records
      reach    : 0x00000002 (Reachable)

    resolver #2
      domain   : local
      options  : mdns
      timeout  : 5
    """

    // Captured verbatim from real `route -n get default` output.
    static let routeOutput = """
       route to: default
    destination: default
           mask: default
        gateway: 192.168.178.1
      interface: en0
          flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
    """

    static let hardwarePortsOutput = """

    Hardware Port: Ethernet Adapter (en3)
    Device: en3
    Ethernet Address: 92:8d:f6:ef:cb:fa

    Hardware Port: Wi-Fi
    Device: en0
    Ethernet Address: 68:5e:dd:49:f8:9b
    """

    func testParsesDisabledProxyAsNil() {
        let (http, https) = RealNetworkStateSnapshot.parseProxy(Self.proxyDisabledOutput)
        XCTAssertNil(http)
        XCTAssertNil(https)
    }

    func testParsesEnabledProxyHostAndPort() {
        let (http, https) = RealNetworkStateSnapshot.parseProxy(Self.proxyEnabledOutput)
        XCTAssertEqual(http, "127.0.0.1:8080")
        XCTAssertEqual(https, "127.0.0.1:8080")
    }

    func testParsesPrimaryResolverNameservers() {
        let servers = RealNetworkStateSnapshot.parsePrimaryDNS(Self.dnsOutput)
        XCTAssertEqual(servers, ["1.1.1.1", "8.8.8.8"])
    }

    func testParsesDefaultGateway() {
        XCTAssertEqual(RealNetworkStateSnapshot.parseGateway(Self.routeOutput), "192.168.178.1")
    }

    func testParsesDefaultInterface() {
        XCTAssertEqual(RealNetworkStateSnapshot.parseDefaultInterface(Self.routeOutput), "en0")
    }

    func testMatchesHardwarePortForDevice() {
        XCTAssertEqual(RealNetworkStateSnapshot.matchHardwarePort(forDevice: "en0", in: Self.hardwarePortsOutput), "Wi-Fi")
        XCTAssertEqual(RealNetworkStateSnapshot.matchHardwarePort(forDevice: "en3", in: Self.hardwarePortsOutput), "Ethernet Adapter (en3)")
        XCTAssertNil(RealNetworkStateSnapshot.matchHardwarePort(forDevice: "en99", in: Self.hardwarePortsOutput))
    }

    func testSplitsHostPort() {
        let result = RealNetworkStateSnapshot.splitHostPort("127.0.0.1:8080")
        XCTAssertEqual(result?.0, "127.0.0.1")
        XCTAssertEqual(result?.1, "8080")
    }

    /// A genuine, read-only smoke test against this machine's real
    /// network configuration: confirms the full snapshot adapter runs
    /// without throwing.
    func testRealSnapshotDoesNotThrow() throws {
        let snapshot = try RealNetworkStateSnapshot().snapshot()
        XCTAssertTrue(snapshot.dnsServers.count >= 0) // exercises the real call path without assuming this machine's config
    }
}
