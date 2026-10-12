//
//  AppTrafficLogger.swift
//
//  Temporary, PII-safe diagnostic instrumentation. Captures every REST +
//  GraphQL network call and every analytics/log event to a structured JSONL
//  file in the app's Documents directory, for empirical traffic analysis.
//
//  Reference template for the app-traffic-analysis skill. Adapt the integration
//  calls to your app's networking and logging choke points; keep the design
//  rules intact (see notes at the bottom and the instrumentation guide).
//
//  Safety properties:
//  - Never records request/response bodies, headers, query-item values, or raw
//    log-field values (only an explicit safe allowlist).
//  - REST paths are normalized so identifier segments become `{id}`.
//  - Enforces a maximum file size, then stops and marks the capture truncated.
//  - Deletes prior capture files on session start (one capture per session).
//  - Inert in Release builds; intended to be removed once analysis is complete.
//

import Foundation

/// Lightweight, thread-safe diagnostic logger that appends one JSON object per
/// line (JSONL) describing network and log traffic.
final class AppTrafficLogger {

    enum Source: String {
        case rest
        case graphql
    }

    static let shared = AppTrafficLogger()

    /// Master switch. Enabled for debug and QA builds; compiled off otherwise.
    /// Replace `QA_BUILD_CONFIGURATION` with your project's QA compile flag.
    #if DEBUG || QA_BUILD_CONFIGURATION
    nonisolated(unsafe) static var isEnabled = true
    #else
    nonisolated(unsafe) static var isEnabled = false
    #endif

    /// Maximum capture-file size in bytes. Once exceeded, writing stops and a
    /// final `truncated` session marker is emitted. Prevents runaway files.
    nonisolated(unsafe) static var maxFileSizeBytes = 10 * 1024 * 1024 // 10 MB

    /// Log-field keys whose VALUES are safe (non-PII) to record.
    private static let safeValueKeys: Set<String> = [
        "event", "eventname", "statusCode", "status",
        "method", "networkType", "env", "operationName", "responseTime"
    ]

    private static let newline = Data([0x0A])

    private let queue = DispatchQueue(label: "com.app.traffic-logger")

    private var fileHandle: FileHandle?
    private(set) var fileURL: URL?
    private var bytesWritten = 0
    private var didTruncate = false

    private let isoFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"
        return formatter
    }()

    private let fileStampFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyyMMdd-HHmmss"
        return formatter
    }()

    private init() {}

    // MARK: - Session

    /// Deletes prior capture files, opens a fresh timestamped JSONL file for this
    /// session, writes a `session`/`start` marker, and prints its path.
    func startSession() {
        guard Self.isEnabled else { return }

        queue.async {
            let directory = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]

            // One capture per session: remove any prior capture files.
            if let existing = try? FileManager.default.contentsOfDirectory(
                at: directory, includingPropertiesForKeys: nil) {
                for url in existing where url.lastPathComponent.hasPrefix("app-traffic-")
                    && url.pathExtension == "jsonl" {
                    try? FileManager.default.removeItem(at: url)
                }
            }

            let name = "app-traffic-\(self.fileStampFormatter.string(from: Date())).jsonl"
            let url = directory.appendingPathComponent(name)

            FileManager.default.createFile(atPath: url.path, contents: nil)
            self.fileHandle = try? FileHandle(forWritingTo: url)
            self.fileURL = url
            self.bytesWritten = 0
            self.didTruncate = false

            print("📄 [AppTrafficLogger] session file: \(url.path)")

            self.writeLocked(["kind": "session", "event": "start"])
        }
    }

    /// Writes a `session`/`end` marker (and closes the file).
    func endSession() {
        guard Self.isEnabled else { return }
        queue.async {
            self.writeLocked(["kind": "session", "event": "end", "truncated": self.didTruncate])
            try? self.fileHandle?.close()
            self.fileHandle = nil
        }
    }

    // MARK: - Recording

    /// Records a single network call (REST or GraphQL).
    /// - For GraphQL, pass `info` to derive status/latency and key names; values
    ///   are never stored except the safe allowlist.
    func recordNetwork(source: Source,
                       method: String? = nil,
                       path: String? = nil,
                       name: String? = nil,
                       status: Int? = nil,
                       ms: Double? = nil,
                       ok: Bool? = nil,
                       info: [String: String]? = nil) {
        guard Self.isEnabled else { return }

        var record: [String: Any] = ["kind": "network", "source": source.rawValue]
        if let method { record["method"] = method }
        if let path { record["path"] = normalize(path) }
        if let name { record["name"] = name }

        if let status {
            record["status"] = status
        } else if let statusString = info?["statusCode"], let parsed = Int(statusString) {
            record["status"] = parsed
        }

        if let ms {
            record["ms"] = Int(ms.rounded())
        } else if let responseTime = info?["responseTime"], let parsed = Double(responseTime) {
            record["ms"] = Int(parsed.rounded())
        }

        if let ok { record["ok"] = ok }

        if let info {
            record["keys"] = Array(info.keys).sorted()
            let safe = info.filter { Self.safeValueKeys.contains($0.key) }
            if !safe.isEmpty { record["safe"] = safe }
        }

        write(record)
    }

    /// Records a single log/analytics event. Stores the event name, offline
    /// flag, the `info` key NAMES, and only the safe-allowlisted values.
    func recordLog(eventName: String, offline: Bool, info: [String: String]?) {
        guard Self.isEnabled else { return }

        var record: [String: Any] = [
            "kind": "log",
            "name": eventName,
            "offline": offline
        ]

        if let info {
            record["keys"] = Array(info.keys).sorted()
            let safe = info.filter { Self.safeValueKeys.contains($0.key) }
            if !safe.isEmpty { record["safe"] = safe }
        }

        write(record)
    }

    // MARK: - Private

    private func write(_ object: [String: Any]) {
        queue.async { self.writeLocked(object) }
    }

    /// Must be called on `queue`. Appends one JSONL record, enforcing the size cap.
    private func writeLocked(_ object: [String: Any]) {
        guard let handle = fileHandle, !didTruncate else { return }

        var payload = object
        payload["ts"] = isoFormatter.string(from: Date())

        guard let data = try? JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys]) else {
            return
        }

        // Enforce the max file size: stop and mark truncated once exceeded.
        if bytesWritten + data.count + 1 > Self.maxFileSizeBytes {
            if let marker = try? JSONSerialization.data(
                withJSONObject: ["kind": "session", "event": "end", "truncated": true,
                                 "ts": isoFormatter.string(from: Date())],
                options: [.sortedKeys]) {
                try? handle.write(contentsOf: marker)
                try? handle.write(contentsOf: Self.newline)
            }
            didTruncate = true
            try? handle.close()
            fileHandle = nil
            print("⚠️ [AppTrafficLogger] max file size reached; capture truncated.")
            return
        }

        try? handle.write(contentsOf: data)
        try? handle.write(contentsOf: Self.newline)
        bytesWritten += data.count + 1
    }

    /// Collapses identifier-like path segments (numeric, UUID, or long opaque
    /// tokens) to `{id}` so endpoints group together and no ids leak.
    private func normalize(_ path: String) -> String {
        func isIdentifier(_ segment: String) -> Bool {
            if !segment.isEmpty, segment.allSatisfy({ $0.isNumber }) { return true }
            if segment.count >= 16, segment.allSatisfy({ $0.isHexDigit || $0 == "-" }) { return true }
            if segment.count >= 20 { return true }
            return false
        }

        // Drop any query string; record the path component only.
        let pathOnly = path.split(separator: "?", maxSplits: 1).first.map(String.init) ?? path

        let normalized = pathOnly
            .split(separator: "/")
            .map { isIdentifier(String($0)) ? "{id}" : String($0) }
            .joined(separator: "/")

        return "/" + normalized
    }
}

//
//  INTEGRATION (adapt to your app's choke points)
//  ----------------------------------------------
//  App launch:
//      AppTrafficLogger.shared.startSession()
//  App termination / background:
//      AppTrafficLogger.shared.endSession()
//
//  REST client, in the single `fire`/`send` completion (request + response in scope):
//      let start = Date()
//      // ... perform request ...
//      AppTrafficLogger.shared.recordNetwork(
//          source: .rest,
//          method: request.method.rawValue,
//          path: request.path,
//          status: response.response?.statusCode,
//          ms: Date().timeIntervalSince(start) * 1000,
//          ok: response.error == nil)
//
//  GraphQL logging/response callback:
//      AppTrafficLogger.shared.recordNetwork(source: .graphql, name: operationName, info: info)
//
//  Analytics/log enqueue method (record BEFORE any offline guard):
//      AppTrafficLogger.shared.recordLog(
//          eventName: event.name,
//          offline: !Reachability.isReachable,
//          info: event.info)
//
