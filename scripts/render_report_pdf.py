#!/usr/bin/env python3
"""
Render a detailed traffic-analysis PDF from a findings JSON.

Takes the output of analyze_traffic.py and produces a shareable PDF with an
executive summary, session overview, per-endpoint tables, duplicate bursts,
latency distribution, logging noise, and recommendations.

Usage:
    python render_report_pdf.py findings.json -o report.pdf
        [--title "App Traffic Analysis"] [--app "<name>"] [--session "<desc>"]

Requires reportlab (`pip install reportlab`). If it is not installed, the script
writes a Markdown report instead and prints how to get the PDF.
"""

import argparse
import json
import sys


# ------------------------------ shared helpers ----------------------------- #

def load(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def fmt(value, suffix=""):
    return f"{value}{suffix}" if value is not None else "—"


def exec_summary_lines(f):
    """Human-readable headline sentences derived from the findings."""
    s, net, lat, log, bursts = (
        f["session"], f["network"], f["latency"], f["logging"], f["duplicate_bursts"])
    lines = [
        f"Captured a {s['duration_minutes']}-minute session"
        + (" (capture truncated at the size cap)" if s["truncated"] else "") + ".",
        f"{net['total']} network calls "
        f"({', '.join(f'{k} {v}' for k, v in net['by_source'].items())}) "
        f"at {fmt(net['calls_per_minute'])} calls/min.",
        f"{log['total']} log events at {fmt(log['events_per_minute'])}/min "
        f"— {fmt(log['mirror_ratio'], 'x')} the network volume.",
    ]
    if lat["count"]:
        lines.append(
            f"Latency p50 {fmt(lat['p50'], lat['unit'])}, p99 {fmt(lat['p99'], lat['unit'])}, "
            f"max {fmt(lat['max'], lat['unit'])}.")
    if bursts["total_bursts"]:
        lines.append(
            f"{bursts['total_bursts']} duplicate burst(s) totalling "
            f"{bursts['duplicate_calls']} redundant calls.")
    if net["top_endpoints"]:
        top = net["top_endpoints"][0]
        lines.append(f"Busiest endpoint: {top['endpoint']} "
                     f"({top['count']} calls, {top['share_pct']}%).")
    return lines


# ------------------------------- PDF (reportlab) --------------------------- #

def render_pdf(f, out_path, title, app, session_desc):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle)

    styles = getSampleStyleSheet()
    h1 = styles["Heading1"]
    h2 = styles["Heading2"]
    body = styles["BodyText"]
    small = ParagraphStyle("small", parent=body, fontSize=8, leading=10)
    meta = ParagraphStyle("meta", parent=body, textColor=colors.grey, fontSize=9)

    doc = SimpleDocTemplate(out_path, pagesize=letter,
                            topMargin=0.7 * inch, bottomMargin=0.7 * inch,
                            leftMargin=0.7 * inch, rightMargin=0.7 * inch,
                            title=title)
    story = []

    def table(data, col_widths=None, header=True):
        t = Table(data, colWidths=col_widths, repeatRows=1 if header else 0)
        style = [
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.lightgrey),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.Color(0.96, 0.96, 0.98)]),
        ]
        if header:
            style += [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2d2d44")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ]
        t.setStyle(TableStyle(style))
        return t

    # ---- Title ----
    story.append(Paragraph(title, h1))
    subtitle = " · ".join(x for x in [app, session_desc] if x)
    if subtitle:
        story.append(Paragraph(subtitle, meta))
    s = f["session"]
    story.append(Paragraph(
        f"Session {fmt(s['start'])} → {fmt(s['end'])} "
        f"({s['duration_minutes']} min)" + (" — TRUNCATED" if s["truncated"] else ""), meta))
    story.append(Spacer(1, 0.2 * inch))

    # ---- Executive summary ----
    story.append(Paragraph("Executive Summary", h2))
    for line in exec_summary_lines(f):
        story.append(Paragraph("• " + line, body))
    story.append(Spacer(1, 0.15 * inch))

    # ---- Session / volume overview ----
    net, log, lat = f["network"], f["logging"], f["latency"]
    story.append(Paragraph("Overview", h2))
    overview = [
        ["Metric", "Value"],
        ["Duration", f"{s['duration_minutes']} min"],
        ["Network calls", f"{net['total']}  ({fmt(net['calls_per_minute'])}/min)"],
        ["  by source", ", ".join(f"{k}: {v}" for k, v in net["by_source"].items()) or "—"],
        ["  by method", ", ".join(f"{k}: {v}" for k, v in net["by_method"].items()) or "—"],
        ["Log events", f"{log['total']}  ({fmt(log['events_per_minute'])}/min)"],
        ["Log : network ratio", fmt(log["mirror_ratio"], "x")],
        ["Latency p50 / p99 / max",
         f"{fmt(lat['p50'])} / {fmt(lat['p99'])} / {fmt(lat['max'])} {lat['unit']}"],
        ["Slow calls (≥ %sms)" % lat["slow_threshold_ms"], str(lat["slow_calls"])],
        ["Duplicate bursts",
         f"{f['duplicate_bursts']['total_bursts']} "
         f"({f['duplicate_bursts']['duplicate_calls']} redundant calls)"],
        ["Errors", str(f["errors"]["total"])],
    ]
    story.append(table(overview, col_widths=[2.4 * inch, 4.0 * inch]))
    story.append(Spacer(1, 0.2 * inch))

    # ---- Top endpoints ----
    story.append(Paragraph("Top Endpoints", h2))
    rows = [["Endpoint", "Calls", "Share", "p50", "p99"]]
    for e in net["top_endpoints"][:15]:
        rows.append([e["endpoint"], str(e["count"]), f"{e['share_pct']}%",
                     fmt(e["p50_ms"]), fmt(e["p99_ms"])])
    story.append(table(rows, col_widths=[3.4 * inch, 0.7 * inch, 0.7 * inch,
                                         0.8 * inch, 0.8 * inch]))
    story.append(Spacer(1, 0.2 * inch))

    # ---- Duplicate bursts ----
    b = f["duplicate_bursts"]
    story.append(Paragraph(
        f"Duplicate Bursts (within {b['window_seconds']}s)", h2))
    if b["by_endpoint"]:
        rows = [["Endpoint", "Bursts", "Redundant", "Worst (calls / span)"]]
        for e in b["by_endpoint"][:15]:
            w = e["worst"]
            rows.append([e["endpoint"], str(e["bursts"]), str(e["duplicate_calls"]),
                         f"{w['count']} in {w['span_seconds']}s"])
        story.append(table(rows, col_widths=[3.2 * inch, 0.8 * inch, 1.0 * inch, 1.4 * inch]))
        story.append(Paragraph(
            "Repeated identical calls in a short window indicate missing request "
            "coalescing or debounce — concurrent callers should share one in-flight "
            "request.", small))
    else:
        story.append(Paragraph("No duplicate bursts detected.", body))
    story.append(Spacer(1, 0.2 * inch))

    # ---- Errors ----
    story.append(Paragraph("Errors & Retries", h2))
    if f["errors"]["by_endpoint"]:
        rows = [["Endpoint", "Count", "Statuses", "Wasted", "No backoff?"]]
        for e in f["errors"]["by_endpoint"][:15]:
            statuses = ", ".join(f"{k}×{v}" for k, v in e["statuses"].items()) or "—"
            rows.append([e["endpoint"], str(e["count"]), statuses,
                         f"{round(e['wasted_ms'] / 1000.0, 1)}s",
                         "yes" if e["no_backoff"] else "no"])
        story.append(table(rows, col_widths=[2.9 * inch, 0.6 * inch, 1.5 * inch,
                                             0.7 * inch, 0.9 * inch]))
    else:
        story.append(Paragraph("No failing calls in this capture.", body))
    story.append(Spacer(1, 0.2 * inch))

    # ---- Logging noise ----
    story.append(Paragraph("Logging Noise", h2))
    rows = [["Event", "Count", "Share"]]
    for e in log["top_events"][:15]:
        rows.append([e["name"], str(e["count"]), f"{e['share_pct']}%"])
    story.append(table(rows, col_widths=[4.0 * inch, 1.2 * inch, 1.2 * inch]))
    if log["mirror_ratio"] and log["mirror_ratio"] >= 1.0:
        story.append(Paragraph(
            f"Logging volume is {log['mirror_ratio']}x network volume — high-frequency "
            "audit/mirror events are strong candidates to drop or sample.", small))
    story.append(Spacer(1, 0.2 * inch))

    # ---- Recommendations ----
    story.append(Paragraph("Recommendations", h2))
    for i, rec in enumerate(f["recommendations"], start=1):
        story.append(Paragraph(f"{i}. {rec}", body))
        story.append(Spacer(1, 0.04 * inch))

    doc.build(story)


# ------------------------------- Markdown fallback ------------------------- #

def render_markdown(f, out_path, title, app, session_desc):
    s, net, log, lat = f["session"], f["network"], f["logging"], f["latency"]
    lines = [f"# {title}", ""]
    sub = " · ".join(x for x in [app, session_desc] if x)
    if sub:
        lines.append(f"*{sub}*\n")
    lines.append(f"Session {fmt(s['start'])} → {fmt(s['end'])} ({s['duration_minutes']} min)"
                 + (" — **TRUNCATED**" if s["truncated"] else "") + "\n")

    lines.append("## Executive Summary\n")
    lines += [f"- {x}" for x in exec_summary_lines(f)]
    lines.append("")

    lines.append("## Top Endpoints\n")
    lines.append("| Endpoint | Calls | Share | p50 | p99 |")
    lines.append("|---|---|---|---|---|")
    for e in net["top_endpoints"][:15]:
        lines.append(f"| {e['endpoint']} | {e['count']} | {e['share_pct']}% | "
                     f"{fmt(e['p50_ms'])} | {fmt(e['p99_ms'])} |")
    lines.append("")

    b = f["duplicate_bursts"]
    lines.append(f"## Duplicate Bursts (within {b['window_seconds']}s)\n")
    if b["by_endpoint"]:
        lines.append("| Endpoint | Bursts | Redundant | Worst |")
        lines.append("|---|---|---|---|")
        for e in b["by_endpoint"][:15]:
            w = e["worst"]
            lines.append(f"| {e['endpoint']} | {e['bursts']} | {e['duplicate_calls']} | "
                         f"{w['count']} in {w['span_seconds']}s |")
    else:
        lines.append("None detected.")
    lines.append("")

    lines.append("## Errors & Retries\n")
    if f["errors"]["by_endpoint"]:
        lines.append("| Endpoint | Count | Statuses | Wasted | No backoff? |")
        lines.append("|---|---|---|---|---|")
        for e in f["errors"]["by_endpoint"][:15]:
            statuses = ", ".join(f"{k}×{v}" for k, v in e["statuses"].items()) or "—"
            lines.append(f"| {e['endpoint']} | {e['count']} | {statuses} | "
                         f"{round(e['wasted_ms'] / 1000.0, 1)}s | "
                         f"{'yes' if e['no_backoff'] else 'no'} |")
    else:
        lines.append("None.")
    lines.append("")

    lines.append("## Logging Noise\n")
    lines.append(f"Total {log['total']} events, {fmt(log['events_per_minute'])}/min, "
                 f"mirror ratio {fmt(log['mirror_ratio'], 'x')}.\n")
    lines.append("| Event | Count | Share |")
    lines.append("|---|---|---|")
    for e in log["top_events"][:15]:
        lines.append(f"| {e['name']} | {e['count']} | {e['share_pct']}% |")
    lines.append("")

    lines.append("## Recommendations\n")
    for i, rec in enumerate(f["recommendations"], start=1):
        lines.append(f"{i}. {rec}")

    with open(out_path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


def main():
    ap = argparse.ArgumentParser(description="Render a traffic-analysis PDF from findings JSON.")
    ap.add_argument("findings", help="Path to findings.json from analyze_traffic.py.")
    ap.add_argument("-o", "--output", default="traffic-analysis-report.pdf",
                    help="Output PDF path (default: traffic-analysis-report.pdf).")
    ap.add_argument("--title", default="App Traffic Analysis", help="Report title.")
    ap.add_argument("--app", default="", help="App name shown in the header.")
    ap.add_argument("--session", default="", help="Short description of what was exercised.")
    args = ap.parse_args()

    findings = load(args.findings)

    try:
        import reportlab  # noqa: F401
    except ImportError:
        md_path = args.output.rsplit(".", 1)[0] + ".md"
        render_markdown(findings, md_path, args.title, args.app, args.session)
        print(f"reportlab is not installed — wrote Markdown report to {md_path} instead.")
        print("For the PDF: pip install reportlab, then re-run this command.")
        sys.exit(0)

    render_pdf(findings, args.output, args.title, args.app, args.session)
    print(f"PDF report written to {args.output}")


if __name__ == "__main__":
    main()
