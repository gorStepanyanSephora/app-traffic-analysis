# Instrumentation Guide

| Version | Date |
|---|---|
| 1 | 2026-10-12 |

How to instrument an app's traffic choke points and emit the canonical JSONL the
analyzer consumes. The goal is maximum coverage with minimum edits, and zero PII.

## 1. Finding the choke points

Most apps route all traffic through a few shared components. Instrument those,
not individual call sites. You are typically looking for three:

| Choke point | What to look for | What to record |
|---|---|---|
| **REST** | The single HTTP client function that fires every request and has both the request and the response in scope (e.g. a `fire`/`send`/`execute` method wrapping URLSession/Alamofire/OkHttp/axios/requests). | method, path, status, latency, ok |
| **GraphQL** | The client's response or logging callback — the hook invoked once per operation with the operation name and timing. | operation name, status, latency |
| **Logging / analytics / telemetry** | The one enqueue/add method every analytics or Splunk/log event passes through before being sent or batched. | event name, offline flag, field names |

Heuristics to locate them:

- Search for the networking library's entry point and find the internal wrapper
  the app calls everywhere (grep for the request method, then find its single
  definition).
- For GraphQL, search for where responses are logged or where a per-operation
  completion/splunk callback is invoked.
- For logging, search for the analytics manager's `add`/`log`/`track`/`enqueue`
  method — the funnel before network send, so you capture offline events too.

Instrument as close to the funnel as possible. For logging, record **before**
any reachability/offline guard so events dropped or deferred while offline are
still counted.

## 2. Canonical JSONL schema

One JSON object per line. The analyzer reads these `kind` values:

### Network call
```json
{"ts":"2026-10-12T14:03:11.482Z","kind":"network","source":"rest","method":"GET","path":"/v2/sd/visits","status":200,"ms":374,"ok":true,"keys":["env","statusCode"],"safe":{"env":"prod"}}
```
- `source`: `"rest"` or `"graphql"`.
- `path`: normalized (ids → `{id}`). REST only; omit for GraphQL.
- `name`: operation name (GraphQL) — omit for REST.
- `status`: integer HTTP status (optional).
- `ms`: latency in milliseconds, integer (optional).
- `ok`: boolean success (optional).
- `keys`: sorted list of the field *names* present on the event (optional).
- `safe`: map of allowlisted, non-PII field values only (optional).

### Log / analytics / telemetry event
```json
{"ts":"2026-10-12T14:03:11.500Z","kind":"log","name":"api_request","offline":false,"keys":["event","statusCode"],"safe":{"event":"api_request"}}
```
- `name`: event name.
- `offline`: whether the device was offline when enqueued (optional).
- `keys` / `safe`: as above.
- `"splunk"` is accepted as an alias for `"log"`.

### Session markers (optional but recommended)
```json
{"ts":"2026-10-12T14:00:00.000Z","kind":"session","event":"start"}
{"ts":"2026-10-12T14:09:24.000Z","kind":"session","event":"end","truncated":false}
```
`truncated: true` tells the analyzer the file hit its size cap and the capture is
partial.

All records carry `ts` — ISO-8601 UTC with milliseconds. Timestamps drive the
burst-window and session-duration math, so keep them precise and monotonic.

## 3. PII-safety rules (non-negotiable)

This observer sees real user traffic. Treat every value as sensitive unless
proven otherwise.

- **Never** record bodies, headers, query-item values, cookies, tokens, or raw
  log-field values.
- Record **structure, not content**: method, normalized path, status, latency,
  event name, and field *names*.
- Keep a **short allowlist** of known-safe value keys and record only those in
  `safe` (e.g. `event`, `statusCode`, `status`, `method`, `networkType`, `env`,
  `operationName`, `responseTime`).
- **Normalize paths**: collapse a segment to `{id}` when it is all-numeric, looks
  like a UUID/hex token (≥16 hex/dash chars), or is long and opaque (≥20 chars).
- Query strings must never appear in `path` — record the path component only.

## 4. Operational rules

- **Build gating.** Enable only in debug/QA; compile the logger out of release
  (e.g. `#if DEBUG || QA_FLAG`). The static enable switch defaults to off in
  release.
- **File size cap.** Track bytes written; stop appending at a configurable max
  (default ~10 MB) and emit the `session`/`truncated` marker. Prevents runaway
  files on long sessions.
- **Per-session cleanup.** On start, delete prior capture files in the target
  directory, then open one fresh timestamped file. You always analyze a single
  clean session.
- **Thread safety / low overhead.** Serialize writes on a dedicated queue.
  Building a record off the hot path should be negligible; never block the
  request thread on disk I/O.
- **Discoverability.** Print the capture file path on session start.

## 5. Porting to other stacks

The Swift template in `logger-templates/swift-traffic-logger.swift` is the
reference. To port:

- **Android/Kotlin:** a singleton with a single-thread `Executor` or a
  `Channel`; hook OkHttp's `Interceptor` for REST, the Apollo interceptor for
  GraphQL, and your analytics dispatcher for logs. Write with a buffered
  `FileWriter`; cap by checking `file.length()`.
- **Web/JS:** wrap `fetch`/`axios` interceptors and your analytics client;
  append to an in-memory array and download as a `.jsonl` blob, or POST to a
  tiny local collector. Same schema, same rules.
- **Backend:** middleware around the HTTP handler and the logging adapter; write
  JSONL to a rotating file. Backends usually already have structured logs — you
  may be able to derive the same schema from existing logs instead of
  instrumenting.

Whatever the stack, keep the schema and the safety rules identical so the same
analyzer and report work everywhere.
