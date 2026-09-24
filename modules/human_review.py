"""
modules/human_review.py – Interactive CLI for reviewing and approving
findings before submission. Human approval is mandatory.
"""

import os
import subprocess
from typing import List, Dict


SEVERITY_COLORS = {
    "critical": "\033[91m",   # red
    "high":     "\033[93m",   # yellow
    "medium":   "\033[94m",   # blue
    "low":      "\033[92m",   # green
    "info":     "\033[97m",   # white
}
RESET = "\033[0m"


def _color(text: str, severity: str) -> str:
    color = SEVERITY_COLORS.get(severity.lower(), "")
    return f"{color}{text}{RESET}"


def review_findings(report_results: List[Dict]) -> List[Dict]:
    """
    Interactive CLI review. For each finding the human can:
      [a] Approve → mark for submission
      [s] Skip    → do not submit
      [v] View    → open the full markdown report
      [q] Quit    → stop reviewing
    Returns list of approved findings.
    """
    approved = []
    total = len(report_results)

    print("\n" + "="*60)
    print("  HUMAN REVIEW — Bug Bounty Bot")
    print(f"  {total} finding(s) to review")
    print("="*60)

    for i, result in enumerate(report_results, 1):
        finding = result["finding"]
        file_path = result.get("file_path", "")
        severity = finding.get("severity", "info")

        print(f"\n[{i}/{total}] {_color(severity.upper(), severity)} — {finding.get('title', 'Untitled')}")
        print(f"  URL      : {finding.get('url', 'N/A')}")
        print(f"  Type     : {finding.get('vuln_type', 'N/A')}")
        print(f"  CVSS     : {finding.get('cvss_score', 'N/A')}")
        print(f"  Report   : {file_path}")
        print()

        while True:
            choice = input("  Action → [a]pprove / [s]kip / [v]iew report / [q]uit: ").strip().lower()
            if choice == "a":
                result["approved"] = True
                approved.append(result)
                print("  ✅ Approved for submission.")
                break
            elif choice == "s":
                result["approved"] = False
                print("  ⏭ Skipped.")
                break
            elif choice == "v":
                # Open report in default editor/viewer
                try:
                    if os.name == "nt":
                        os.startfile(file_path)
                    else:
                        subprocess.Popen(["xdg-open", file_path])
                except Exception as e:
                    print(f"  Could not open file: {e}")
                    print(f"  Read it manually: {file_path}")
            elif choice == "q":
                print("\n  Review stopped by user.")
                return approved
            else:
                print("  Invalid choice. Enter a, s, v, or q.")

    print(f"\n  Review complete. {len(approved)}/{total} approved.")
    return approved
