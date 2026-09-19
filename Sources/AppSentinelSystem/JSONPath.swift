import Foundation

/// Tiny helper for defensively reading nested values out of a
/// `JSONSerialization` object graph, used when parsing `eslogger`'s NDJSON
/// output. `eslogger`'s exact field layout has shifted across macOS
/// releases (in particular how a process's pid is represented inside its
/// audit token), so lookups here try several known shapes rather than
/// assuming one.
enum JSONPath {
    static func value(_ root: Any?, _ path: [String]) -> Any? {
        var current = root
        for key in path {
            guard let dict = current as? [String: Any] else { return nil }
            current = dict[key]
        }
        return current
    }

    static func string(_ root: Any?, _ path: [String]) -> String? {
        value(root, path) as? String
    }

    static func int32(_ root: Any?, _ path: [String]) -> Int32? {
        if let n = value(root, path) as? NSNumber { return n.int32Value }
        if let s = value(root, path) as? String, let n = Int32(s) { return n }
        return nil
    }

    /// Reads a pid from a process object, trying (in order): a direct
    /// `pid` field, `audit_token.pid`, and the raw BSD audit token array
    /// form `audit_token.val[5]` (index 5 of the audit token is the pid,
    /// per XNU's `audit_token_to_pid`).
    static func pid(ofProcessAt path: [String], in root: Any?) -> Int32? {
        if let direct = int32(root, path + ["pid"]) { return direct }
        if let viaToken = int32(root, path + ["audit_token", "pid"]) { return viaToken }
        if let tokenArray = value(root, path + ["audit_token", "val"]) as? [Any], tokenArray.count > 5,
           let n = tokenArray[5] as? NSNumber {
            return n.int32Value
        }
        return nil
    }

    static func executablePath(ofProcessAt path: [String], in root: Any?) -> String? {
        string(root, path + ["executable", "path"])
    }
}
