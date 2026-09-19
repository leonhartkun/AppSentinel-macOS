import Foundation

/// Tracks the explicit, time-limited certificate enrollment a session may
/// grant with `--certificate-enrollment`. At most one newly-added
/// certificate may be recorded during the window. AppSentinel never grants
/// trust itself — macOS still controls that — this only decides whether a
/// certificate *addition* is treated as expected or as a critical
/// violation.
public struct CertificateEnrollmentWindow: Sendable, Equatable {
    public let start: Date
    public let duration: TimeInterval
    public private(set) var enrolledCount: Int

    public init(start: Date, duration: TimeInterval) {
        self.start = start
        self.duration = duration
        self.enrolledCount = 0
    }

    public var end: Date { start.addingTimeInterval(duration) }

    public func isActive(at date: Date) -> Bool {
        date >= start && date <= end
    }

    public enum EnrollmentResult: Equatable {
        /// The certificate is the first one seen inside an active window.
        case permitted
        /// A window is active but this is already the second (or later)
        /// certificate seen inside it.
        case violatesSecondCertificate
        /// No window is active, or the window has already elapsed.
        case violatesOutsideWindow
    }

    /// Evaluate (and, if permitted, record) a new-certificate observation.
    /// This mutates enrollment state only when the certificate is
    /// permitted, so callers can safely re-evaluate without side effects
    /// on a rejected attempt.
    public mutating func evaluate(at date: Date) -> EnrollmentResult {
        guard isActive(at: date) else { return .violatesOutsideWindow }
        guard enrolledCount == 0 else { return .violatesSecondCertificate }
        enrolledCount += 1
        return .permitted
    }
}
