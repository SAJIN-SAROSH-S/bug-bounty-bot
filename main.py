"""
main.py – Bug Bounty Bot Orchestrator
======================================
Usage:
    python -m bug_bounty_bot.main

Ensure your ANTHROPIC_API_KEY is set in config.py or as env var.
Only run against authorized, in-scope targets.
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bug_bounty_bot.database.db import init_db, new_session, close_session, save_finding, save_report
from bug_bounty_bot.modules.target_manager import load_targets, select_program, get_all_start_urls
from bug_bounty_bot.modules.scope_checker import ScopeChecker
from bug_bounty_bot.modules.crawler import Crawler
from bug_bounty_bot.modules.passive_scanner import PassiveScanner
from bug_bounty_bot.modules.active_scanner import ActiveScanner
from bug_bounty_bot.modules.deduplicator import deduplicate
from bug_bounty_bot.modules.report_writer import ReportWriter
from bug_bounty_bot.modules.human_review import review_findings
from bug_bounty_bot.modules.submission import submit_findings


def main():
    print("\n" + "="*60)
    print("  🔍 Bug Bounty Bot — Authorized Security Research Tool")
    print("="*60)
    print("\n⚠️  WARNING: Only run this against targets you are")
    print("   authorized to test (bug bounty programs, your own apps).")
    confirm = input("\n  Confirm you have authorization? [yes/no]: ").strip().lower()
    if confirm != "yes":
        print("  Aborted. Please obtain authorization before scanning.")
        sys.exit(0)

    # ── 1. Initialize Database ────────────────────────────────────────────
    print("\n[1/8] Initializing database...")
    init_db()

    # ── 2. Load Targets ───────────────────────────────────────────────────
    print("[2/8] Loading targets...")
    programs = load_targets()
    program = select_program(programs)
    print(f"  Selected: {program['name']} ({program['platform']})")

    start_urls = get_all_start_urls(program)
    if not start_urls:
        print("  No start URLs configured. Exiting.")
        sys.exit(1)

    # ── 3. Setup Scope Checker ────────────────────────────────────────────
    print("[3/8] Setting up scope checker...")
    scope = ScopeChecker(program)

    all_findings = []

    for start_url in start_urls:
        if not scope.is_in_scope(start_url):
            print(f"  ⚠️  Start URL out of scope: {start_url}")
            continue

        print(f"\n{'─'*60}")
        print(f"  Target: {start_url}")
        print(f"{'─'*60}")

        # Create scan session
        session_id = new_session(program["name"], start_url)

        # ── 4. Crawl ──────────────────────────────────────────────────────
        print(f"\n[4/8] Crawling {start_url}...")
        crawler = Crawler(scope)
        pages = crawler.crawl(start_url)

        if not pages:
            print("  No pages discovered. Skipping.")
            continue

        # ── 5. Passive Scan ───────────────────────────────────────────────
        print("\n[5/8] Running passive scans...")
        passive = PassiveScanner()
        passive_findings = passive.scan_all(pages)

        # ── 6. Active Scan ────────────────────────────────────────────────
        print("\n[6/8] Running active scans...")
        active = ActiveScanner(scope)
        active_findings = active.scan_all(pages, start_url)

        combined = passive_findings + active_findings

        # ── 7. Deduplicate ────────────────────────────────────────────────
        print("\n[7/8] Deduplicating findings...")
        unique_findings = deduplicate(combined)

        # Save to DB
        for finding in unique_findings:
            finding["_db_id"] = save_finding(session_id, finding)

        all_findings.extend(unique_findings)
        close_session(session_id)

    # ── 8. Generate Reports ───────────────────────────────────────────────
    if not all_findings:
        print("\n✅ No findings detected. Scan complete.")
        sys.exit(0)

    print(f"\n[8/8] Total findings: {len(all_findings)}")
    print("\nGenerating AI-powered reports with Claude...")

    writer = ReportWriter()
    report_results = writer.generate_all(all_findings)

    # Save reports to DB
    for result in report_results:
        finding = result["finding"]
        db_id = finding.get("_db_id")
        if db_id:
            save_report(db_id, result["report_md"])

    # ── Human Review ──────────────────────────────────────────────────────
    print("\n" + "="*60)
    print("  📋 HUMAN REVIEW PHASE")
    print("  Review each finding before submission.")
    print("="*60)

    approved = review_findings(report_results)

    # ── Submission ────────────────────────────────────────────────────────
    if approved:
        submit_findings(approved)
    else:
        print("\n  No findings approved for submission.")

    print("\n✅ Bug Bounty Bot session complete.")


if __name__ == "__main__":
    main()
