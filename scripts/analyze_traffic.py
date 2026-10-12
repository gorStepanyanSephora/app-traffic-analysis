#!/usr/bin/env python3
"""
Analyze a captured traffic JSONL file and emit a findings JSON.

Reads the canonical schema produced by the traffic logger (see the
instrumentation guide) and computes the signals that matter for cutting wasteful
traffic: duplicate bursts, top endpoints, latency percentiles, error/no-backoff
patterns, and logging noise.

Usage:
    python analyze_traffic.py <capture.jsonl> [-o findings.json]
                              [--burst-window 1.0] [--slow-ms 2000] [--quiet]

The findings JSON is consumed by render_report_pdf.py. Pure standard library.
"""

import argparse
import json
import sys
from collections import defaultdict, Counter
from datetime import datetime


# ----------------------------- parsing helpers ----------------------------- #

def parse_ts(value):
    """Parse an ISO-8601 timestamp (trailing 'Z' allowed) to a datetime, or None."""
    if not value or not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def load_records(path):
    """Yield (record, line_no) for each valid JSON line; warn on bad lines."""
    records = []
    with open(path, "r", encoding="utf-8") as handle:
        for line_no, raw in enumerate(handle, start=1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                records.append((json.loads(raw), line_no))
            except json.JSONDecodeError:
                print(f"  (skipped malformed line {line_no})", file=sys.stderr)
    return records


def percentile(sorted_values, pct):
    """Nearest-rank percentile over a pre-sorted list; None if empty."""
    if not sorted_values:
        return None
    if len(sorted_values) == 1:
        return sorted_values[0]
    rank = max(0, min(len(sorted_values) - 1,
                      int(round((pct / 100.0) * (len(sorted_values) - 1)))))
    return sorted_values[rank]


def endpoint_key(rec):
    """Stable grouping key for a network record."""
    source = rec.get("source", "rest")
    if source == "graphql":
        return f"GQL {rec.get('name', '(unnamed)')}"
    method = rec.get("method", "?")
    path = rec.get("path", "(no path)")
    return f"{method} {path}"


# ----------------------------- analysis passes ----------------------------- #

def analyze_bursts(timestamps, window_seconds):
    """Given sorted datetimes for one endpoint, find clusters of calls within
    `window_seconds` of the cluster start. Returns (bursts, duplicate_calls,
    worst) where worst = {count, span_seconds}."""
    bursts = 0
    duplicate_calls = 0
    worst = {"count": 0, "span_seconds": 0.0}
    i = 0
    n = len(timestamps)
    while i < n:
        j = i + 1
        while j < n and (timestamps[j] - timestamps[i]).total_seconds() <= window_seconds:
            j += 1
        cluster = j - i
        if cluster >= 2:
            bursts += 1
            duplicate_calls += cluster - 1  # all but the first are redundant
            span = (timestamps[j - 1] - timestamps[i]).total_seconds()
            if cluster > worst["count"]:
                worst = {"count": cluster, "span_seconds": round(span, 3)}
        i = j if cluster >= 2 else i + 1
    return bursts, duplicate_calls, worst


def no_backoff(timestamps):
    """Heuristic: repeated failures with non-increasing gaps => no backoff.
    True when there are >=2 retries and gaps don't trend upward."""
    if len(timestamps) < 3:
        return len(timestamps) >= 2  # 2 identical failures, no widening possible
    gaps = [(timestamps[i + 1] - timestamps[i]).total_seconds()
            for i in range(len(timestamps) - 1)]
    # Backoff would roughly increase gaps; flag when the last gap isn't clearly
    # larger than the first.
    return gaps[-1] <= gaps[0] * 1.5


def analyze(records, burst_window, slow_ms):
    network = [r for r, _ in records if r.get("kind") == "network"]
    logs = [r for r, _ in records if r.get("kind") in ("log", "splunk")]
    sessions = [r for r, _ in records if r.get("kind") == "session"]

    all_ts = [parse_ts(r.get("ts")) for r, _ in records]
    all_ts = sorted(t for t in all_ts if t)

    # ---- session window ----
    start = next((parse_ts(s.get("ts")) for s in sessions if s.get("event") == "start"), None)
    end = next((parse_ts(s.get("ts")) for s in sessions if s.get("event") == "end"), None)
    if start is None and all_ts:
        start = all_ts[0]
    if end is None and all_ts:
        end = all_ts[-1]
    duration_s = (end - start).total_seconds() if (start and end) else 0.0
    duration_min = duration_s / 60.0 if duration_s else 0.0
    truncated = any(s.get("truncated") for s in sessions)

    # ---- network ----
    by_source = Counter(r.get("source", "rest") for r in network)
    by_method = Counter(r.get("method") for r in network if r.get("method"))

    grouped = defaultdict(list)
    for r in network:
        grouped[endpoint_key(r)].append(r)

    total_net = len(network)

    top_endpoints = []
    for key, recs in grouped.items():
        lat = sorted(r["ms"] for r in recs if isinstance(r.get("ms"), (int, float)))
        top_endpoints.append({
            "endpoint": key,
            "count": len(recs),
            "share_pct": round(100.0 * len(recs) / total_net, 1) if total_net else 0.0,
            "p50_ms": percentile(lat, 50),
            "p99_ms": percentile(lat, 99),
        })
    top_endpoints.sort(key=lambda e: e["count"], reverse=True)

    # ---- duplicate bursts ----
    burst_by_endpoint = []
    total_bursts = 0
    total_dupes = 0
    for key, recs in grouped.items():
        ts = sorted(t for t in (parse_ts(r.get("ts")) for r in recs) if t)
        bursts, dupes, worst = analyze_bursts(ts, burst_window)
        if bursts:
            total_bursts += bursts
            total_dupes += dupes
            burst_by_endpoint.append({
                "endpoint": key, "bursts": bursts,
                "duplicate_calls": dupes, "worst": worst,
            })
    burst_by_endpoint.sort(key=lambda e: e["duplicate_calls"], reverse=True)

    # ---- latency ----
    all_lat = sorted(r["ms"] for r in network if isinstance(r.get("ms"), (int, float)))
    latency = {
        "unit": "ms",
        "count": len(all_lat),
        "p50": percentile(all_lat, 50),
        "p90": percentile(all_lat, 90),
        "p99": percentile(all_lat, 99),
        "max": all_lat[-1] if all_lat else None,
        "slow_threshold_ms": slow_ms,
        "slow_calls": sum(1 for v in all_lat if v >= slow_ms),
    }

    # ---- errors / no-backoff ----
    def is_error(r):
        if r.get("ok") is False:
            return True
        status = r.get("status")
        return isinstance(status, int) and status >= 400

    error_groups = defaultdict(list)
    for r in network:
        if is_error(r):
            error_groups[endpoint_key(r)].append(r)

    errors_by_endpoint = []
    total_errors = 0
    for key, recs in error_groups.items():
        total_errors += len(recs)
        ts = sorted(t for t in (parse_ts(r.get("ts")) for r in recs) if t)
        statuses = Counter(str(r.get("status")) for r in recs if r.get("status") is not None)
        wasted_ms = sum(r["ms"] for r in recs if isinstance(r.get("ms"), (int, float)))
        errors_by_endpoint.append({
            "endpoint": key,
            "count": len(recs),
            "statuses": dict(statuses),
            "wasted_ms": int(wasted_ms),
            "no_backoff": no_backoff(ts) if len(recs) >= 2 else False,
        })
    errors_by_endpoint.sort(key=lambda e: e["count"], reverse=True)

    # ---- logging ----
    total_logs = len(logs)
    log_events = Counter(r.get("name", "(unnamed)") for r in logs)
    top_events = [{
        "name": name, "count": count,
        "share_pct": round(100.0 * count / total_logs, 1) if total_logs else 0.0,
    } for name, count in log_events.most_common()]
    logging = {
        "total": total_logs,
        "events_per_minute": round(total_logs / duration_min, 1) if duration_min else None,
        "mirror_ratio": round(total_logs / total_net, 2) if total_net else None,
        "events_per_network_call": round(total_logs / total_net, 2) if total_net else None,
        "offline_events": sum(1 for r in logs if r.get("offline")),
        "top_events": top_events,
    }

    findings = {
        "session": {
            "start": start.isoformat() if start else None,
            "end": end.isoformat() if end else None,
            "duration_seconds": round(duration_s, 1),
            "duration_minutes": round(duration_min, 1),
            "truncated": truncated,
        },
        "network": {
            "total": total_net,
            "by_source": dict(by_source),
            "by_method": dict(by_method),
            "calls_per_minute": round(total_net / duration_min, 1) if duration_min else None,
            "top_endpoints": top_endpoints,
        },
        "duplicate_bursts": {
            "window_seconds": burst_window,
            "total_bursts": total_bursts,
            "duplicate_calls": total_dupes,
            "by_endpoint": burst_by_endpoint,
        },
        "latency": latency,
        "errors": {"total": total_errors, "by_endpoint": errors_by_endpoint},
        "logging": logging,
    }
    findings["recommendations"] = build_recommendations(findings)
    return findings


def build_recommendations(f):
    """Translate measured signals into concrete, defensible recommendations."""
    recs = []
    net = f["network"]
    total = net["total"] or 1

    for e in net["top_endpoints"][:3]:
        if e["share_pct"] >= 20:
            recs.append(
                f"{e['endpoint']} is {e['share_pct']}% of all network calls "
                f"({e['count']}/{total}). Investigate caching or coalescing — a single "
                f"endpoint dominating traffic usually means redundant fetches.")

    for b in f["duplicate_bursts"]["by_endpoint"][:3]:
        w = b["worst"]
        recs.append(
            f"{b['endpoint']} shows {b['bursts']} duplicate burst(s) "
            f"({b['duplicate_calls']} redundant calls; worst: {w['count']} calls in "
            f"{w['span_seconds']}s). Add request coalescing/debounce so concurrent "
            f"callers share one in-flight request.")

    for e in f["errors"]["by_endpoint"][:3]:
        if e["no_backoff"] and e["count"] >= 2:
            secs = round(e["wasted_ms"] / 1000.0, 1)
            recs.append(
                f"{e['endpoint']} failed {e['count']}x (statuses {e['statuses']}) with no "
                f"backoff, ~{secs}s wasted. Add exponential backoff and a retry cap.")

    lat = f["latency"]
    if lat["p99"] and lat["p50"] and lat["p99"] >= 10 * max(lat["p50"], 1):
        recs.append(
            f"Latency is highly skewed (p50 {lat['p50']}{lat['unit']} vs p99 "
            f"{lat['p99']}{lat['unit']}, max {lat['max']}{lat['unit']}). A few very slow "
            f"calls drive tail latency — profile the slowest endpoints.")

    log = f["logging"]
    if log["mirror_ratio"] and log["mirror_ratio"] >= 1.0:
        recs.append(
            f"Logging volume is {log['mirror_ratio']}x network volume "
            f"({log['total']} events). Audit/mirror events likely duplicate network "
            f"data — drop or sample the highest-frequency events.")
    if log["top_events"]:
        top = log["top_events"][0]
        if top["share_pct"] >= 15:
            recs.append(
                f"Log event '{top['name']}' is {top['share_pct']}% of all events "
                f"({top['count']}). Confirm it is actionable; if not, remove or sample it.")

    if f["session"]["truncated"]:
        recs.append(
            "Capture hit the file-size cap and is truncated — totals are a lower "
            "bound. Re-run with a larger cap or a shorter session for complete data.")

    if not recs:
        recs.append("No major waste patterns detected in this capture.")
    return recs


# --------------------------------- output ---------------------------------- #

def print_summary(f):
    s, net, lat, log = f["session"], f["network"], f["latency"], f["logging"]
    print(f"\nSession: {s['duration_minutes']} min"
          + (" (TRUNCATED)" if s["truncated"] else ""))
    print(f"Network: {net['total']} calls "
          f"({', '.join(f'{k}:{v}' for k, v in net['by_source'].items())}), "
          f"{net['calls_per_minute']}/min")
    print(f"Logging: {log['total']} events, {log['events_per_minute']}/min, "
          f"mirror ratio {log['mirror_ratio']}x")
    if lat["count"]:
        print(f"Latency: p50 {lat['p50']}{lat['unit']}  p99 {lat['p99']}{lat['unit']}  "
              f"max {lat['max']}{lat['unit']}")
    print(f"Duplicate bursts: {f['duplicate_bursts']['total_bursts']} "
          f"({f['duplicate_bursts']['duplicate_calls']} redundant calls)")
    print("\nTop endpoints:")
    for e in net["top_endpoints"][:5]:
        print(f"  {e['count']:>4}  {e['share_pct']:>5}%  {e['endpoint']}")
    print("\nRecommendations:")
    for r in f["recommendations"]:
        print(f"  • {r}")
    print()


def main():
    ap = argparse.ArgumentParser(description="Analyze a traffic JSONL capture.")
    ap.add_argument("capture", help="Path to the .jsonl capture file.")
    ap.add_argument("-o", "--output", default="findings.json",
                    help="Where to write the findings JSON (default: findings.json).")
    ap.add_argument("--burst-window", type=float, default=1.0,
                    help="Seconds within which repeated identical calls count as a "
                         "duplicate burst (default: 1.0).")
    ap.add_argument("--slow-ms", type=int, default=2000,
                    help="Latency (ms) at/above which a call is counted 'slow' "
                         "(default: 2000).")
    ap.add_argument("--quiet", action="store_true", help="Suppress the console summary.")
    args = ap.parse_args()

    records = load_records(args.capture)
    if not records:
        print("No records found in capture.", file=sys.stderr)
        sys.exit(1)

    findings = analyze(records, args.burst_window, args.slow_ms)

    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(findings, handle, indent=2)

    if not args.quiet:
        print_summary(findings)
    print(f"Findings written to {args.output}")


if __name__ == "__main__":
    main()
