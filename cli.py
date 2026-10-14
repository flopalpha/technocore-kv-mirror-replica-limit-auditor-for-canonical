"""Command line wrapper for the KV mirror replica-limit auditor."""

import argparse
import auditor


def run_text(text, limit, window):
    entries = auditor.parse_room_export(text)
    artifacts = auditor.collect_artifacts(entries)
    findings = auditor.check_limits(artifacts, limit=limit, seq_window=window)
    gaps = auditor.seq_gaps(artifacts)
    report = auditor.build_report(entries, artifacts, findings, gaps, limit=limit, seq_window=window)
    return report


def main():
    ap = argparse.ArgumentParser(description="Audit KV mirror replicas and proof links offline.")
    ap.add_argument("input", help="Path to pasted room export text file")
    ap.add_argument("--limit", type=int, default=2, help="Replica limit N")
    ap.add_argument("--window", type=int, default=500, help="Seq window")
    ap.add_argument("--out-md", default="", help="Write markdown report path")
    ap.add_argument("--out-json", default="", help="Write json report path")
    ap.add_argument("--print", dest="do_print", action="store_true", help="Print markdown to stdout")
    args = ap.parse_args()
    with open(args.input, "r", encoding="utf-8") as f:
        text = f.read()
    report = run_text(text, args.limit, args.window)
    md = auditor.render_markdown(report)
    js = auditor.render_json(report)
    if args.out_md:
        with open(args.out_md, "w", encoding="utf-8") as f:
            f.write(md)
    if args.out_json:
        with open(args.out_json, "w", encoding="utf-8") as f:
            f.write(js)
    if args.do_print or (not args.out_md and not args.out_json):
        print(md)


if __name__ == "__main__":
    main()
