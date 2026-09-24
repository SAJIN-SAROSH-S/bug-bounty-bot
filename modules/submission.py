"""
modules/submission.py – Submit approved reports.
Supports: copy to clipboard, save to file, email draft, HackerOne/Bugcrowd info.
"""

import json
import smtplib
import subprocess
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Dict
from pathlib import Path


def copy_to_clipboard(text: str):
    """Copy text to clipboard (Windows/Linux/macOS)."""
    try:
        import subprocess, sys
        if sys.platform == "win32":
            subprocess.run(["clip"], input=text.encode("utf-8"), check=True)
        elif sys.platform == "darwin":
            subprocess.run(["pbcopy"], input=text.encode("utf-8"), check=True)
        else:
            subprocess.run(["xclip", "-selection", "clipboard"],
                           input=text.encode("utf-8"), check=True)
        print("  📋 Report copied to clipboard.")
    except Exception as e:
        print(f"  Could not copy to clipboard: {e}")


def send_email_draft(
    finding: Dict,
    report_md: str,
    smtp_host: str,
    smtp_port: int,
    sender: str,
    password: str,
    recipient: str,
):
    """Send a report draft as an email (plain text + markdown attachment)."""
    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"[Bug Report] {finding.get('severity','?').upper()} – {finding.get('title','')}"
    msg["From"] = sender
    msg["To"] = recipient

    body = MIMEText(report_md, "plain")
    msg.attach(body)

    with smtplib.SMTP_SSL(smtp_host, smtp_port) as server:
        server.login(sender, password)
        server.sendmail(sender, recipient, msg.as_string())

    print(f"  📧 Email sent to {recipient}")


def submit_findings(approved_results: List[Dict]):
    """
    Interactive submission handler for approved findings.
    Guides the user to the correct platform submission page.
    """
    if not approved_results:
        print("\n[Submission] No approved findings to submit.")
        return

    print("\n" + "="*60)
    print("  SUBMISSION")
    print("="*60)
    print("\nHow would you like to submit your approved reports?\n")
    print("  [1] Show HackerOne submission instructions")
    print("  [2] Show Bugcrowd submission instructions")
    print("  [3] Copy report to clipboard (paste into platform)")
    print("  [4] Save summary JSON")
    print("  [5] Email draft (configure SMTP in config)")
    print("  [0] Skip / Done\n")

    choice = input("Choice: ").strip()

    for result in approved_results:
        finding = result["finding"]
        report_md = result.get("report_md", "")
        file_path = result.get("file_path", "")

        print(f"\n--- {finding.get('title', 'Finding')} ---")

        if choice == "1":
            print("""
  HackerOne Submission Steps:
  1. Go to the program's page on hackerone.com
  2. Click "Submit Report"
  3. Fill in the vulnerability type and affected asset
  4. Copy & paste from your report file:
     """ + file_path + """
  5. Attach any screenshots/PoC files
  6. Submit and await triage
            """)

        elif choice == "2":
            print("""
  Bugcrowd Submission Steps:
  1. Go to the program's page on bugcrowd.com
  2. Click "Submit a Bug"
  3. Select vulnerability type and target
  4. Copy & paste from your report file:
     """ + file_path + """
  5. Submit and await triage
            """)

        elif choice == "3":
            copy_to_clipboard(report_md)

        elif choice == "4":
            summary_path = file_path.replace(".md", "_summary.json")
            summary = {
                "title": finding.get("title"),
                "url": finding.get("url"),
                "severity": finding.get("severity"),
                "vuln_type": finding.get("vuln_type"),
                "cvss_score": finding.get("cvss_score"),
                "report_file": file_path,
            }
            with open(summary_path, "w") as f:
                json.dump(summary, f, indent=2)
            print(f"  💾 Summary saved → {summary_path}")

        elif choice == "5":
            print("\n  Email submission requires SMTP configuration.")
            print("  Add your SMTP settings to config.py and call send_email_draft() directly.")

        else:
            print("  Skipping submission.")
