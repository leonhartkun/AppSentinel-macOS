import Foundation

/// Builds a minimal, harmless `.app` bundle backed by a shell script, used
/// as the launch target in integration acceptance tests. Never touches
/// anything outside the caller-supplied temporary directory.
enum FixtureApp {
    @discardableResult
    static func make(name: String, scriptBody: String, in directory: URL) throws -> String {
        let bundleDirectory = directory.appendingPathComponent("\(name).app")
        let contentsDirectory = bundleDirectory.appendingPathComponent("Contents")
        let macOSDirectory = contentsDirectory.appendingPathComponent("MacOS")
        try FileManager.default.createDirectory(at: macOSDirectory, withIntermediateDirectories: true)

        let infoPlist: [String: Any] = [
            "CFBundleExecutable": name,
            "CFBundleIdentifier": "com.appsentinel.fixture.\(name)",
            "CFBundlePackageType": "APPL"
        ]
        let plistData = try PropertyListSerialization.data(fromPropertyList: infoPlist, format: .xml, options: 0)
        try plistData.write(to: contentsDirectory.appendingPathComponent("Info.plist"))

        let scriptURL = macOSDirectory.appendingPathComponent(name)
        let fullScript = "#!/bin/sh\n" + scriptBody + "\n"
        try fullScript.write(to: scriptURL, atomically: true, encoding: .utf8)

        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: scriptURL.path)

        return bundleDirectory.path
    }

    /// A fixture that spawns one child process, waits for it, and exits —
    /// nothing else. Used to verify launch/descendant-tracking/normal-exit
    /// behavior.
    static func normalExitScript() -> String {
        """
        (sleep 0.4) &
        CHILD=$!
        wait $CHILD
        exit 0
        """
    }

    /// A fixture that records its own pid and a long-lived grandchild's
    /// pid to files (so the test can verify termination directly via
    /// `kill(pid, 0)`), then — after a short delay — creates a file inside
    /// `sensitiveHome/.ssh`, simulating an unauthorized write to a
    /// protected path.
    static func protectedPathViolationScript(sensitiveHome: String, rootPIDFile: String, grandchildPIDFile: String) -> String {
        """
        echo $$ > '\(rootPIDFile)'
        (sh -c 'echo $$ > "\(grandchildPIDFile)"; sleep 60') &
        GRANDCHILD=$!
        sleep 0.4
        mkdir -p '\(sensitiveHome)/.ssh'
        echo 'fake-key-material-not-a-real-secret' > '\(sensitiveHome)/.ssh/id_ed25519'
        wait $GRANDCHILD
        """
    }
}
