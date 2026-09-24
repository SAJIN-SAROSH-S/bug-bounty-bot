"""
manual_report_tool.py – Manual testing assistant for programs that
prohibit automated scanning (e.g. manual-only bug bounty programs).

Usage:
    py -m bug_bounty_bot.manual_report_tool

You manually test the app, then feed your findings here.
The tool uses Claude to generate a professional Bugcrowd-ready report.
"""

import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bug_bounty_bot.database.db import init_db, new_session, save_finding, save_report
from bug_bounty_bot.modules.report_writer import ReportWriter
from bug_bounty_bot.modules.human_review import review_findings
from bug_bounty_bot.modules.submission import submit_findings
from bug_bounty_bot.config import TARGETS_FILE

# ── Standard out-of-scope vuln types ──────────────────────────────────────
OUT_OF_SCOPE_TYPES = {
    "missing_security_header", "rate_limiting", "self_xss", "ssl_tls",
    "clickjacking", "logout_csrf", "content_spoofing", "weak_captcha",
    "brute_force", "username_enumeration", "version_disclosure",
    "spf_dmarc", "source_code_disclosure", "jwt_ajax"
}

SEVERITY_MAP = {
    "1": ("P1", "critical", 1500),
    "2": ("P2", "high", 900),
    "3": ("P3", "medium", 300),
    "4": ("P4", "low", 100),
}

VULN_TYPES = {
    "1":  "Cross Instance Data Leakage/Access",
    "2":  "Remote Code Execution (RCE)",
    "3":  "Server-Side Request Forgery (SSRF)",
    "4":  "Stored XSS",
    "5":  "Reflected XSS",
    "6":  "Cross-Site Request Forgery (CSRF)",
    "7":  "SQL Injection",
    "8":  "XML External Entity (XXE)",
    "9":  "IDOR / Access Control",
    "10": "Path/Directory Traversal",
    "11": "Other (describe below)",
}


def print_banner():
    print("\n" + "="*60)
    print("  🎯 Bug Bounty Assistant — Manual Report Tool")
    print("  ⚠️  MANUAL TESTING ONLY — no automated scanning")
    print("="*60)
    print("""
Reward chart:
  P1 (Critical) → $1,500
  P2 (High)     → $900
  P3 (Medium)   → $300
  P4 (Low)      → $100

✅ In scope:  test-instance.example.com (your authorized test instance)
              Target web and API endpoints
❌ Out scope: third-party dependencies, production/customer data,
              missing headers, rate limiting, SSL, self-XSS
""")


def ask(prompt: str, required: bool = True) -> str:
    while True:
        val = input(f"  {prompt}: ").strip()
        if val or not required:
            return val
        print("  (required — please enter a value)")


def multiline(prompt: str) -> str:
    print(f"  {prompt}")
    print("  (Enter multiple lines. Type '---' on its own line to finish)")
    lines = []
    while True:
        line = input("  > ")
        if line.strip() == "---":
            break
        lines.append(line)
    return "\n".join(lines)


def collect_finding() -> dict:
    print("\n" + "-"*50)
    print("  NEW FINDING")
    print("-"*50)

    # Vulnerability type
    print("\n  Vulnerability Type:")
    for k, v in VULN_TYPES.items():
        print(f"    [{k}] {v}")
    vuln_choice = ask("Select number")
    vuln_type = VULN_TYPES.get(vuln_choice, "Other")
    if vuln_type == "Other (describe below)":
        vuln_type = ask("Describe vulnerability type")

    # Severity
    print("\n  Severity / Priority:")
    for k, (p, s, r) in SEVERITY_MAP.items():
        print(f"    [{k}] {p} ({s.upper()}) → ${r}")
    sev_choice = ask("Select severity")
    priority, severity, reward = SEVERITY_MAP.get(sev_choice, ("P3", "medium", 300))

    # Basic info
    url = ask("Affected URL/endpoint (on your test instance)")
    title = ask("Short title for the finding")

    # Description
    print("\n  Description")
    description = multiline("Describe the vulnerability in detail")

    # Steps to reproduce
    print("\n  Steps to Reproduce")
    reproduction = multiline("Step-by-step to reproduce the issue")

    # Evidence
    print("\n  Evidence")
    evidence_raw = multiline("Paste request/response, payloads, screenshots path, etc.")

    # Impact
    print("\n  Impact")
    impact = multiline("What is the security impact?")

    # Remediation
    remediation = ask("Suggested remediation (brief)", required=False)

    finding = {
        "url": url,
        "vuln_type": vuln_type,
        "severity": severity,
        "priority": priority,
        "title": title,
        "description": description,
        "reproduction": reproduction,
        "evidence": {"raw": evidence_raw},
        "impact": impact,
        "remediation": remediation or "Follow OWASP best practices.",
        "cvss_score": {"P1": 9.5, "P2": 7.5, "P3": 5.0, "P4": 3.0}.get(priority, 5.0),
        "estimated_reward": reward,
    }

    print(f"\n  ✅ Finding recorded: [{priority}] {title}")
    print(f"     Estimated reward: ${reward}")
    return finding


def main():
    print_banner()
    init_db()

    session_id = new_session(
        "Sample Bug Bounty Program",
        "test-instance.example.com"
    )

    findings = []
    while True:
        print("\n  What would you like to do?")
        print("  [1] Add a new finding")
        print("  [2] Generate reports for all findings")
        print("  [3] Exit without generating reports")
        choice = input("\n  Choice: ").strip()

        if choice == "1":
            finding = collect_finding()
            finding["_db_id"] = save_finding(session_id, finding)
            findings.append(finding)
            print(f"\n  Total findings so far: {len(findings)}")

        elif choice == "2":
            if not findings:
                print("\n  No findings to report. Add at least one finding first.")
                continue

            total_potential = sum(f.get("estimated_reward", 0) for f in findings)
            print(f"\n  📊 Summary: {len(findings)} finding(s)")
            print(f"  💰 Potential earnings: ${total_potential}")
            print(f"\n  Generating Claude AI reports for {len(findings)} finding(s)...")

            writer = ReportWriter()
            report_results = writer.generate_all(findings)

            for result in report_results:
                fid = result["finding"].get("_db_id")
                if fid:
                    save_report(fid, result["report_md"])

            print("\n" + "="*60)
            print("  📋 REVIEW YOUR REPORTS")
            print("="*60)
            approved = review_findings(report_results)

            if approved:
                print(f"\n  Approved {len(approved)} finding(s) for submission.")
                print("""
  📝 Program Submission Instructions:
  1. Go to your authorized program submission page on Bugcrowd or HackerOne
  2. Click "Submit a Bug"
  3. Select vulnerability type and your test instance as the target
  4. Paste your report (plain text only — no PDF/DOCX)
  5. Attach screenshots/videos as evidence
  6. Submit and await triage
                """)
                submit_findings(approved)
            break

        elif choice == "3":
            print("\n  Exiting. Findings saved to database.")
            break


if __name__ == "__main__":
    main()
