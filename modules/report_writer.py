"""
modules/report_writer.py – Use Claude via OpenRouter to generate
professional bug bounty report drafts from raw findings.
"""

import json
import re
import requests
from typing import Dict
from pathlib import Path
from datetime import datetime

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from bug_bounty_bot.config import (
    LLM_PROVIDER,
    GEMINI_API_KEY, GEMINI_MODEL,
    OPENROUTER_API_KEY, OPENROUTER_BASE_URL, CLAUDE_MODEL,
    REPORTS_DIR
)


SYSTEM_PROMPT = """You are a professional security researcher writing bug bounty vulnerability reports.
Generate clear, concise, and actionable reports following bug bounty platform standards.
Include: title, severity, summary, impact, steps to reproduce, evidence, and remediation.
Use markdown formatting. Be precise and professional."""

REPORT_TEMPLATE = """
Generate a professional bug bounty report for the following finding:

**Vulnerability Type:** {vuln_type}
**Affected URL:** {url}
**Severity:** {severity}
**CVSS Score:** {cvss_score}
**Title:** {title}

**Raw Description:**
{description}

**Evidence:**
{evidence}

**Steps to Reproduce:**
{reproduction}

**Suggested Remediation:**
{remediation}

Please write a full professional bug bounty report in markdown with these sections:
1. ## Summary
2. ## Vulnerability Details
3. ## Impact
4. ## Steps to Reproduce
5. ## Evidence
6. ## Remediation
7. ## References (if applicable)

Be specific, actionable, and professional.
"""


class ReportWriter:
    def __init__(self):
        Path(REPORTS_DIR).mkdir(parents=True, exist_ok=True)
        self.provider = LLM_PROVIDER.lower()

    def _call_gemini(self, prompt: str) -> str:
        import time
        if not GEMINI_API_KEY:
            raise ValueError("GEMINI_API_KEY is not set. Set it in config.py or via $env:GEMINI_API_KEY.")
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent?key={GEMINI_API_KEY}"
        payload = {
            "contents": [
                {"parts": [{"text": prompt}]}
            ],
            "systemInstruction": {
                "parts": [{"text": SYSTEM_PROMPT}]
            },
            "generationConfig": {
                "maxOutputTokens": 2048,
                "temperature": 0.2
            }
        }
        for attempt in range(3):
            resp = requests.post(url, json=payload, timeout=60)
            if resp.status_code == 200:
                data = resp.json()
                return data["candidates"][0]["content"]["parts"][0]["text"]
            elif resp.status_code in (429, 503) and attempt < 2:
                time.sleep(2 * (attempt + 1))
                continue
            else:
                resp.raise_for_status()

    def _call_openrouter(self, prompt: str) -> str:
        if not OPENROUTER_API_KEY:
            raise ValueError("OPENROUTER_API_KEY is not set.")
        headers = {
            "Authorization": f"Bearer {OPENROUTER_API_KEY}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/bug-bounty-bot",
            "X-Title": "Bug Bounty Bot",
        }
        payload = {
            "model": CLAUDE_MODEL,
            "max_tokens": 2048,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
        }
        resp = requests.post(
            f"{OPENROUTER_BASE_URL}/chat/completions",
            headers=headers,
            json=payload,
            timeout=60,
        )
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]

    def generate_report(self, finding: Dict) -> str:
        prompt = REPORT_TEMPLATE.format(
            vuln_type=finding.get("vuln_type", "unknown"),
            url=finding.get("url", "N/A"),
            severity=finding.get("severity", "unknown"),
            cvss_score=finding.get("cvss_score", "N/A"),
            title=finding.get("title", "Untitled"),
            description=finding.get("description", ""),
            evidence=json.dumps(finding.get("evidence", {}), indent=2),
            reproduction=finding.get("reproduction", ""),
            remediation=finding.get("remediation", ""),
        )

        print(f"  [ReportWriter] Generating report using {self.provider.upper()} for: {finding['title'][:60]}...")

        if self.provider == "gemini":
            return self._call_gemini(prompt)
        elif self.provider == "openrouter":
            return self._call_openrouter(prompt)
        else:
            raise ValueError(f"Unknown LLM_PROVIDER: {self.provider}")

    def save_report_to_file(self, finding: Dict, report_md: str) -> str:
        """Save a report to the reports/ directory and return file path."""
        url_part = finding.get("url", "").split("/")[-1][:20]
        raw_slug = f"{finding.get('vuln_type', 'finding')}_{url_part}"
        # Sanitize for Windows filename safety (remove ?, :, *, etc.)
        safe_slug = re.sub(r'[^a-zA-Z0-9_\-]', '_', raw_slug)

        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"{REPORTS_DIR}/{timestamp}_{safe_slug}.md"

        with open(filename, "w", encoding="utf-8") as f:
            f.write(f"# Bug Bounty Report\n\n")
            f.write(f"**Generated:** {datetime.utcnow().isoformat()}Z\n\n")
            f.write(f"**Status:** PENDING HUMAN REVIEW\n\n")
            f.write("---\n\n")
            f.write(report_md)

        print(f"  [ReportWriter] Saved -> {filename}")
        return filename

    def generate_all(self, findings: list) -> list:
        """Generate reports for all findings. Returns list of (finding, report_md, file_path)."""
        results = []
        for finding in findings:
            try:
                report_md = self.generate_report(finding)
                file_path = self.save_report_to_file(finding, report_md)
                results.append({
                    "finding": finding,
                    "report_md": report_md,
                    "file_path": file_path,
                })
            except Exception as e:
                print(f"  [ReportWriter] ERROR for {finding.get('title', '?')}: {e}")
        return results

