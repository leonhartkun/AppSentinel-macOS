import Foundation

/// All terminal output is Chinese-first, per AppSentinel's requirement
/// that the user interface communicate in Chinese even though code and
/// APIs stay in English.
struct TerminalOutput {
    func info(_ message: String) {
        print("ℹ️  \(message)")
    }

    func success(_ message: String) {
        print("✅ \(message)")
    }

    func warning(_ message: String) {
        print("⚠️  \(message)")
    }

    func critical(_ message: String) {
        print("🛑 \(message)")
    }

    func line(_ message: String) {
        print(message)
    }
}
