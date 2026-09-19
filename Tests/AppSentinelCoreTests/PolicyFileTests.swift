import XCTest
@testable import AppSentinelCore

final class PolicyFileTests: XCTestCase {
    func testDecodesASimplePolicyDocument() throws {
        let json = """
        {
          "allowedShellExecutables": ["/bin/zsh"],
          "allowedScriptPaths": [],
          "protectedPathExceptions": [],
          "allowedNetworkChanges": [{"field": "httpProxy", "allowedValue": "127.0.0.1:8080"}],
          "certificateEnrollmentWindow": 300
        }
        """
        let policy = try PolicyFile.decode(json.data(using: .utf8)!)
        XCTAssertEqual(policy.allowedShellExecutables, ["/bin/zsh"])
        XCTAssertEqual(policy.allowedNetworkChanges, [NetworkRule(field: .httpProxy, allowedValue: "127.0.0.1:8080")])
        XCTAssertEqual(policy.certificateEnrollmentWindow, 300)
    }

    /// The example policy shipped in `policies/example-policy.json` is
    /// documentation the README points users at; this test keeps it
    /// honest — if the schema changes, this fails until the example is
    /// updated too.
    func testShippedExamplePolicyParses() throws {
        let path = #filePath
            .split(separator: "/", omittingEmptySubsequences: false)
            .dropLast(3) // Tests/AppSentinelCoreTests/PolicyFileTests.swift -> repo root
            .joined(separator: "/") + "/policies/example-policy.json"
        guard FileManager.default.fileExists(atPath: path) else {
            throw XCTSkip("找不到示例策略文件：\(path)")
        }
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        let policy = try PolicyFile.decode(data)
        XCTAssertFalse(policy.allowedShellExecutables.isEmpty)
        XCTAssertNotNil(policy.certificateEnrollmentWindow)
    }
}
