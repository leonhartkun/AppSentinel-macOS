import Foundation

/// What AppSentinel does in response to a critical violation. Building the
/// plan is a pure function of process-tree state; executing it (actually
/// sending signals, restoring the proxy) is the system layer's job.
public struct ResponsePlan: Sendable, Equatable {
    /// Process ids to terminate, in order. Descendants always precede the
    /// root so a parent is never killed while a child that could still
    /// spawn further descendants remains alive.
    public let terminationOrder: [ProcessID]
    public let shouldRestoreNetworkState: Bool
    public let reason: String

    public init(terminationOrder: [ProcessID], shouldRestoreNetworkState: Bool, reason: String) {
        self.terminationOrder = terminationOrder
        self.shouldRestoreNetworkState = shouldRestoreNetworkState
        self.reason = reason
    }

    public static func forCriticalViolation(reason: String, tree: ProcessTreeTracker) -> ResponsePlan {
        ResponsePlan(
            terminationOrder: tree.postOrderPIDs(),
            shouldRestoreNetworkState: true,
            reason: reason
        )
    }
}
