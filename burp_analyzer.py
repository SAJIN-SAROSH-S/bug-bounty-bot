"""
burp_analyzer.py – Main entry point for the Burp Suite workflow.

Usage:
    py -m bug_bounty_bot.burp_analyzer --file burp_export.xml
    py -m bug_bounty_bot.burp_analyzer --file burp_export.xml --target example.com
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bug_bounty_bot.modules.burp_importer import parse_burp_xml, BurpAnalyzer
from bug_bounty_bot.modules.deduplicator import deduplicate
from bug_bounty_bot.modules.report_writer import ReportWriter
from bug_bounty_bot.modules.human_review import review_findings
from bug_bounty_bot.modules.submission import submit_findings
from bug_bounty_bot.database.db import init_db, new_session, save_finding, save_report


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def print_banner():
    import sys, io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    print("\n" + "="*60)
    print("  [*] Bug Bounty Bot - Burp Suite Analyzer")
    print("  Analyzing captured traffic. No requests sent.")
    print("="*60)


def print_summary(findings):
    from collections import Counter
    counts = Counter(f["severity"] for f in findings)
    print(f"\n  📊 Finding Summary:")
    for sev in ["critical", "high", "medium", "low", "info"]:
        n = counts.get(sev, 0)
        if n:
            icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "⚪"}
            print(f"     {icons[sev]} {sev.upper()}: {n}")
    print(f"     Total: {len(findings)}")


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="Analyze Burp Suite XML export for bug bounty findings."
    )
    parser.add_argument(
        "--file", "-f", required=True,
        help="Path to Burp Suite XML export file"
    )
    parser.add_argument(
        "--target", "-t", default=None,
        help="Target domain to filter (e.g. example.com). Comma-separate for multiple."
    )
    parser.add_argument(
        "--program", "-p", default="Sample Bug Bounty Program",
        help="Bug bounty program name for the database session"
    )
    parser.add_argument(
        "--no-interactive", action="store_true",
        help="Skip interactive CLI prompts and save all reports to reports directory"
    )
    args = parser.parse_args()

    xml_file = Path(args.file)
    if not xml_file.exists():
        print(f"\n  ❌ File not found: {args.file}")
        print(f"\n  How to export from Burp Suite:")
        print(f"    1. Open Burp Suite → Proxy → HTTP History")
        print(f"    2. Select all traffic (Ctrl+A)")
        print(f"    3. Right-click → Save items")
        print(f"    4. Save as: burp_export.xml")
        print(f"    5. Run: py -m bug_bounty_bot.burp_analyzer --file burp_export.xml")
        sys.exit(1)

    # Parse scope
    scope_domains = []
    if args.target:
        scope_domains = [d.strip() for d in args.target.split(",")]
        print(f"\n  Scope filter: {scope_domains}")
    else:
        print(f"\n  ⚠️  No --target specified. Analyzing ALL captured traffic.")

    # Init DB
    init_db()
    session_id = new_session(args.program, args.file)

    # Step 1: Parse Burp XML
    print(f"\n[1/5] Parsing Burp XML: {args.file}")
    requests = parse_burp_xml(args.file)
    if not requests:
        print("  No requests found in the export. Make sure you saved items from Proxy → HTTP History.")
        sys.exit(0)

    # Step 2: Analyze
    print(f"\n[2/5] Analyzing {len(requests)} captured requests...")
    analyzer = BurpAnalyzer(scope_domains=scope_domains)
    raw_findings = analyzer.analyze(requests)

    if not raw_findings:
        print("\n  ✅ No candidates flagged. Try browsing more of the target app in Burp.")
        sys.exit(0)

    # Step 3: Deduplicate
    print(f"\n[3/5] Deduplicating findings...")
    findings = deduplicate(raw_findings)

    # Sort by severity
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.get("severity", "info"), 4))
    print_summary(findings)

    # Save to DB
    for f in findings:
        f["_db_id"] = save_finding(session_id, f)

    # Step 4: Generate AI reports
    print(f"\n[4/5] Generating AI reports for {len(findings)} finding(s)...")
    print("      (These are CANDIDATES — you must manually verify each one!)\n")
    writer = ReportWriter()
    report_results = writer.generate_all(findings)

    for result in report_results:
        fid = result["finding"].get("_db_id")
        if fid:
            save_report(fid, result["report_md"])

    # Step 5: Human review
    if args.no_interactive:
        print(f"\n[5/5] Non-interactive mode: {len(report_results)} reports generated.")
        print(f"  All report drafts saved to: bug_bounty_bot/reports/")
        for r in report_results:
            print(f"   - {r.get('file_path')}")
        return

    print(f"\n[5/5] Human Review")
    print("  ⚠️  IMPORTANT: Each finding below is a CANDIDATE.")
    print("  Manually verify in Burp Suite before approving.\n")

    approved = review_findings(report_results)

    if approved:
        print(f"\n  ✅ {len(approved)} finding(s) approved.")
        submit_findings(approved)
    else:
        print("\n  No findings approved. Reports saved for later review.")
        print(f"  Reports directory: bug_bounty_bot/reports/")


if __name__ == "__main__":
    main()
