---
name: app-traffic-analysis
description: >-
  Audit an application's runtime network and logging traffic to find waste —
  excessive or duplicate API calls, missing debounce/coalescing/backoff, and
  noisy or redundant analytics/telemetry logging. Use this whenever someone
  wants to profile, audit, or reduce an app's API traffic, network chatter,
  request volume, Splunk/analytics/log volume, or backend/logging cost, or asks
  "why is this app making so many calls" / "what's generating all this traffic".
  Works for any stack (iOS/Swift, Android/Kotlin, web/JS, backend) by adding
  temporary, PII-safe diagnostic instrumentation that captures every call and
  log event to a structured JSONL file, then analyzing that capture and
  producing a detailed PDF report. Trigger even when the user doesn't say the
  word "traffic" — e.g. reducing systems cost, duplicate requests, or chatty
  logging all qualify.
---

# App Traffic Analysis

Find where an app wastes network calls and logging, back it with real captured
data, and deliver a PDF report that a team can act on.

The core idea: you cannot optimize what you cannot see. Instead of guessing from
the code which endpoints are hot, you insert a tiny, safe observer at the few
points every request and every log event must pass through, run the app through
a realistic session, and let the captured data tell you the truth. Code review
alone misses runtime patterns — duplicate bursts, missing debounce, retries
without backoff, a log that fires four times per save — because those only
appear when the app actually runs.

## The method at a glance

1. **Find the choke points.** Almost every app funnels traffic through a small
   number of shared spots: one place all REST calls pass, one for GraphQL, one
   where analytics/telemetry/log events are enqueued. Instrument there and you
   observe 100% of traffic with ~3 edits instead of touching hundreds of call
   sites.
2. **Drop in a PII-safe JSONL logger.** Add a small logger that appends one JSON
   object per line describing each call and log event. It must be safe by
   design (details below) and must not ship to production users.
3. **Capture a realistic session.** Run the app (ideally on a real device,
   against production-like data) through a representative flow for several
   minutes. The logger writes a `.jsonl` capture file.
4. **Analyze the capture.** Pull the file off the device and run
   `scripts/analyze_traffic.py`. It computes duplicate bursts, top endpoints,
   latency percentiles, error/no-backoff patterns, and logging-noise ratios.
5. **Produce the PDF report.** Run `scripts/render_report_pdf.py` to turn the
   findings into a detailed, shareable PDF describing exactly what is happening
   and what to fix.
6. **Write up the findings** for the team (tickets, recommendations).

## Step 1 — Find the choke points

Read `references/instrumentation-guide.md` for how to locate them per stack and
the canonical JSONL schema the analyzer expects. The short version: look for the
shared network client (the one function that fires every REST request), the
GraphQL client's response/logging hook, and the single enqueue method the
analytics/telemetry layer uses. You want the fewest insertion points that still
see every event.

## Step 2 — Add the logger

Use `references/logger-templates/swift-traffic-logger.swift` as a worked,
drop-in example (Swift/iOS). For other stacks, port the same design — it is
small and the rules matter more than the language. Every logger you write must
honor these, because this instrumentation sees real user data and must never
leak it or ship by accident:

- **PII-safe by construction.** Never record request/response **bodies**,
  **headers**, **query-item values**, or raw log-field **values**. Record
  structural facts only: method, normalized path, status, latency, event name,
  and the *names* of fields. Allow a short, explicit allowlist of known-safe
  values (e.g. `statusCode`, `method`, `env`, `operationName`, `responseTime`).
- **Normalize identifiers in paths.** Collapse id-like path segments (numeric,
  UUID, long opaque tokens) to `{id}` so `/users/12345/cart` and
  `/users/67890/cart` group together and no ids leak.
- **Compiled off in production.** Gate behind a debug/QA build flag so the
  instrumentation is inert (and ideally not even compiled) in release builds.
- **Write to a file, with a size cap.** Append to a JSONL file in app-writable
  storage. Enforce a **maximum file size** (default ~10 MB): once reached, stop
  appending and record a final `truncated` marker so the analyzer knows the
  capture was cut short. This prevents a runaway file during a long session.
- **One capture per session.** On session start, **delete any prior capture
  files** in the directory before opening a fresh, timestamped one, so old
  sessions don't accumulate on the device and you always analyze a clean,
  single-session file.
- **Thread-safe and cheap.** Serialize writes on a dedicated queue; building a
  record must add negligible overhead to the hot path.

Print the capture file path on session start so it's easy to locate and pull
off the device afterward.

## Step 3 — Capture a session

Build the app with instrumentation enabled (debug/QA), run a realistic flow for
several minutes, then retrieve the `.jsonl` file (e.g. via the device's app
container, a file-sharing export, or a debug action). Prefer production-like
data volumes and network conditions — the whole point is to see real behavior.

## Step 4 — Analyze

```bash
python scripts/analyze_traffic.py <capture.jsonl> -o findings.json
```

This prints a summary and writes `findings.json`. It detects:

- **Duplicate bursts** — the same endpoint called repeatedly within a short
  window (default 1.0s), a strong signal of missing request coalescing/debounce.
- **Top endpoints** — which calls dominate the session, by count and share.
- **Latency** — p50 / p90 / p99 / max, overall and per endpoint.
- **Errors & no-backoff** — repeated failing calls to the same endpoint with no
  widening gap between attempts.
- **Logging noise** — event frequency, events-per-minute, and the ratio of
  audit/mirror log events to actual network calls.

See `scripts/analyze_traffic.py --help` for thresholds you can tune (burst
window, latency unit, etc.).

## Step 5 — Produce the PDF report

```bash
python scripts/render_report_pdf.py findings.json -o traffic-analysis-report.pdf \
  --title "App Traffic Analysis" --app "<app name>" --session "<what was exercised>"
```

The PDF is the deliverable. It contains an executive summary, session overview,
per-endpoint tables, the duplicate-burst findings (with worst cases), the
latency distribution, the logging-noise breakdown, and concrete
recommendations. It needs `reportlab` (`pip install reportlab`); if that isn't
installed the script falls back to writing a Markdown/HTML report and tells you
how to get the PDF.

## Step 6 — Write up findings

Translate the report into actionable items: which endpoints to coalesce/debounce,
where to add backoff, which log events to drop or sample. Keep recommendations
tied to the measured numbers in the report so they're defensible.

## Cleaning up

This instrumentation is temporary. Once the analysis is captured, remove the
logger and its insertion points (or leave it dormant behind the build flag if
the team wants to re-run audits later) — it should never reach production users.
