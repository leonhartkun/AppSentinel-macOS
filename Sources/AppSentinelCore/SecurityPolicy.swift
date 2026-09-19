import Foundation

/// An explicitly declared exception to the default network-change policy.
/// `field` names which part of `NetworkState` the rule covers; `value`, if
/// present, restricts the allowance to that exact value (e.g. a specific
/// proxy host). A nil value allows any change to that field.
public struct NetworkRule: Sendable, Equatable, Codable {
    public enum Field: String, Sendable, Codable {
        case httpProxy
        case httpsProxy
        case dns
        case defaultRoute
    }

    public let field: Field
    public let allowedValue: String?

    public init(field: Field, allowedValue: String? = nil) {
        self.field = field
        self.allowedValue = allowedValue
    }
}

/// Interpreters and shells that AppSentinel treats as "a shell" for policy
/// purposes: launching one of these, from within the monitored tree,
/// requires an explicit allow-list entry.
public enum ShellInterpreters {
    public static let defaultPaths: Set<String> = [
        "/bin/sh", "/bin/bash", "/bin/zsh", "/bin/csh", "/bin/tcsh", "/bin/ksh",
        "/usr/bin/osascript", "/usr/bin/perl", "/usr/bin/python3", "/usr/bin/ruby"
    ]

    public static func isShellLike(_ path: String) -> Bool {
        defaultPaths.contains(path)
    }
}

/// The policy AppSentinel enforces for one session. Everything defaults to
/// "not allowed" — expected behavior must be declared explicitly, either on
/// the command line or in a policy file, before the target is launched.
public struct SecurityPolicy: Sendable, Equatable, Codable {
    /// Absolute paths of interpreters/shells the target is allowed to run.
    public var allowedShellExecutables: Set<String>
    /// Absolute paths of scripts the target is allowed to execute.
    public var allowedScriptPaths: Set<String>
    /// Declared exceptions to the default protected-path block rule.
    public var protectedPathExceptions: Set<String>
    /// Declared exceptions to the default network-change block rule.
    public var allowedNetworkChanges: [NetworkRule]
    /// Length of the certificate-enrollment window, if the session grants one.
    public var certificateEnrollmentWindow: TimeInterval?

    public init(
        allowedShellExecutables: Set<String> = [],
        allowedScriptPaths: Set<String> = [],
        protectedPathExceptions: Set<String> = [],
        allowedNetworkChanges: [NetworkRule] = [],
        certificateEnrollmentWindow: TimeInterval? = nil
    ) {
        self.allowedShellExecutables = allowedShellExecutables
        self.allowedScriptPaths = allowedScriptPaths
        self.protectedPathExceptions = protectedPathExceptions
        self.allowedNetworkChanges = allowedNetworkChanges
        self.certificateEnrollmentWindow = certificateEnrollmentWindow
    }

    public static let empty = SecurityPolicy()

    /// Merge a policy-file-declared policy with CLI-declared additions; CLI
    /// flags are additive on top of whatever the policy file allows.
    public func merging(_ other: SecurityPolicy) -> SecurityPolicy {
        SecurityPolicy(
            allowedShellExecutables: allowedShellExecutables.union(other.allowedShellExecutables),
            allowedScriptPaths: allowedScriptPaths.union(other.allowedScriptPaths),
            protectedPathExceptions: protectedPathExceptions.union(other.protectedPathExceptions),
            allowedNetworkChanges: allowedNetworkChanges + other.allowedNetworkChanges,
            certificateEnrollmentWindow: other.certificateEnrollmentWindow ?? certificateEnrollmentWindow
        )
    }
}
