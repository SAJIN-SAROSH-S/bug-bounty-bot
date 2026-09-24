"""
modules/active_scanner.py – Safe active vulnerability checks.
All payloads are non-destructive and designed for detection only.
Only runs against in-scope, authorized targets.
"""

import time
import re
import base64
from urllib.parse import urlencode, urljoin, urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict

import requests

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from bug_bounty_bot.config import (
    REQUEST_TIMEOUT, REQUEST_DELAY, USER_AGENT,
    ENABLE_XSS_CHECK, ENABLE_SQLI_CHECK,
    ENABLE_OPEN_REDIRECT_CHECK, ENABLE_SENSITIVE_FILES_CHECK,
    ENABLE_JWT_CHECK, SENSITIVE_FILE_PATHS
)

SENSITIVE_FILE_PATHS = [
    "/.env", "/.git/HEAD", "/.git/config",
    "/backup.zip", "/backup.tar.gz", "/db.sql",
    "/wp-config.php.bak", "/.DS_Store",
    "/config.json", "/secrets.json", "/credentials.json",
    "/phpinfo.php", "/.htaccess",
    "/api/swagger.json", "/api/openapi.json",
    "/actuator/env", "/actuator/health",
]

# Safe, clearly-marked test payloads
XSS_PAYLOADS = [
    '<script>alert("xss-test-bbbot")</script>',
    '"><img src=x onerror=alert("xss-bbbot")>',
    "javascript:alert('xss-bbbot')",
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "1' AND SLEEP(0)--",   # 0-second sleep = detection without delay
    "1; SELECT 1--",
]

SQLI_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"pg_query\(\):",
    r"sqlite3\.",
    r"syntax error.*sql",
    r"mysql_fetch",
    r"ora-\d{5}",
]

OPEN_REDIRECT_PAYLOADS = [
    "https://evil-bbbot-test.com",
    "//evil-bbbot-test.com",
]


class ActiveScanner:
    def __init__(self, scope_checker):
        self.scope = scope_checker
        self.session = requests.Session()
        self.session.headers["User-Agent"] = USER_AGENT
        self.findings: List[Dict] = []

    def _get(self, url: str, **kwargs) -> requests.Response | None:
        try:
            r = self.session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=False, **kwargs)
            time.sleep(REQUEST_DELAY)
            return r
        except requests.RequestException:
            return None

    def _post(self, url: str, data: dict, **kwargs) -> requests.Response | None:
        try:
            r = self.session.post(url, data=data, timeout=REQUEST_TIMEOUT, allow_redirects=False, **kwargs)
            time.sleep(REQUEST_DELAY)
            return r
        except requests.RequestException:
            return None

    # ── XSS ────────────────────────────────────────────────────────────────
    def check_xss(self, pages: List[Dict]) -> List[Dict]:
        findings = []
        for page in pages:
            url = page["url"]
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            # Test URL parameters
            for param, values in params.items():
                for payload in XSS_PAYLOADS:
                    new_params = dict(params)
                    new_params[param] = [payload]
                    new_query = urlencode(new_params, doseq=True)
                    test_url = urlunparse(parsed._replace(query=new_query))

                    if not self.scope.is_in_scope(test_url):
                        continue

                    resp = self._get(test_url)
                    if resp and payload in resp.text:
                        findings.append({
                            "url": url,
                            "vuln_type": "reflected_xss",
                            "severity": "high",
                            "title": f"Reflected XSS in parameter `{param}`",
                            "description": (
                                f"The parameter `{param}` at `{url}` reflects "
                                f"unsanitized input, enabling JavaScript injection."
                            ),
                            "evidence": {"param": param, "payload": payload, "test_url": test_url},
                            "request_data": f"GET {test_url}",
                            "response_data": resp.text[:2000],
                            "reproduction": (
                                f"1. Navigate to: {test_url}\n"
                                f"2. Observe the payload `{payload}` reflected in the response."
                            ),
                            "remediation": (
                                "Encode all user-supplied input before rendering in HTML. "
                                "Implement a strict Content-Security-Policy."
                            ),
                            "cvss_score": 6.1,
                        })
                        break  # One confirmed payload is enough

            # Test form inputs
            for form in page.get("forms", []):
                action = form["action"] if self.scope.is_in_scope(form["action"]) else url
                for inp in form["inputs"]:
                    if not inp["name"]:
                        continue
                    for payload in XSS_PAYLOADS:
                        data = {i["name"]: i["value"] or "test" for i in form["inputs"]}
                        data[inp["name"]] = payload
                        resp = (self._post(action, data) if form["method"] == "post"
                                else self._get(action + "?" + urlencode(data)))
                        if resp and payload in resp.text:
                            findings.append({
                                "url": action,
                                "vuln_type": "reflected_xss",
                                "severity": "high",
                                "title": f"Reflected XSS in form field `{inp['name']}`",
                                "description": (
                                    f"Form at `{action}` (method={form['method']}) reflects "
                                    f"unsanitized input in field `{inp['name']}`."
                                ),
                                "evidence": {"field": inp["name"], "payload": payload},
                                "request_data": f"{form['method'].upper()} {action} data={data}",
                                "response_data": resp.text[:2000],
                                "reproduction": (
                                    f"1. Submit form at {action}\n"
                                    f"2. Set `{inp['name']}` = `{payload}`\n"
                                    f"3. Observe reflected payload in response."
                                ),
                                "remediation": "Sanitize and encode all form input before output.",
                                "cvss_score": 6.1,
                            })
                            break
        return findings

    # ── SQL Injection ──────────────────────────────────────────────────────
    def check_sqli(self, pages: List[Dict]) -> List[Dict]:
        findings = []
        for page in pages:
            url = page["url"]
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            for param in params:
                for payload in SQLI_PAYLOADS:
                    new_params = dict(params)
                    new_params[param] = [payload]
                    test_url = urlunparse(parsed._replace(query=urlencode(new_params, doseq=True)))

                    if not self.scope.is_in_scope(test_url):
                        continue

                    resp = self._get(test_url)
                    if not resp:
                        continue

                    body_lower = resp.text.lower()
                    for pattern in SQLI_ERROR_PATTERNS:
                        if re.search(pattern, body_lower):
                            findings.append({
                                "url": url,
                                "vuln_type": "sql_injection",
                                "severity": "critical",
                                "title": f"Potential SQL Injection in parameter `{param}`",
                                "description": (
                                    f"SQL error pattern `{pattern}` detected in response "
                                    f"when injecting into parameter `{param}` at `{url}`."
                                ),
                                "evidence": {"param": param, "payload": payload, "pattern": pattern},
                                "request_data": f"GET {test_url}",
                                "response_data": resp.text[:2000],
                                "reproduction": (
                                    f"1. Navigate to: {test_url}\n"
                                    f"2. Observe SQL error in response."
                                ),
                                "remediation": (
                                    "Use parameterized queries / prepared statements. "
                                    "Never concatenate user input into SQL strings."
                                ),
                                "cvss_score": 9.8,
                            })
                            break
        return findings

    # ── Open Redirect ──────────────────────────────────────────────────────
    def check_open_redirect(self, pages: List[Dict]) -> List[Dict]:
        findings = []
        redirect_params = ["redirect", "url", "next", "return", "goto", "to", "dest", "redirect_uri"]

        for page in pages:
            url = page["url"]
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            for param in params:
                if param.lower() not in redirect_params:
                    continue
                for payload in OPEN_REDIRECT_PAYLOADS:
                    new_params = dict(params)
                    new_params[param] = [payload]
                    test_url = urlunparse(parsed._replace(query=urlencode(new_params, doseq=True)))

                    resp = self._get(test_url)
                    if not resp:
                        continue

                    location = resp.headers.get("Location", "")
                    if resp.status_code in (301, 302, 303, 307, 308) and "evil-bbbot-test.com" in location:
                        findings.append({
                            "url": url,
                            "vuln_type": "open_redirect",
                            "severity": "medium",
                            "title": f"Open Redirect via parameter `{param}`",
                            "description": (
                                f"The application redirects to attacker-controlled URLs "
                                f"when `{param}` is set to an external domain."
                            ),
                            "evidence": {"param": param, "payload": payload, "location": location},
                            "request_data": f"GET {test_url}",
                            "response_data": f"HTTP {resp.status_code} Location: {location}",
                            "reproduction": (
                                f"1. Navigate to: {test_url}\n"
                                f"2. Observe redirect to {location}."
                            ),
                            "remediation": (
                                "Validate redirect URLs against an allowlist of trusted domains. "
                                "Reject external redirects."
                            ),
                            "cvss_score": 4.7,
                        })
                        break
        return findings

    # ── Sensitive File Exposure ────────────────────────────────────────────
    def check_sensitive_files(self, base_url: str) -> List[Dict]:
        findings = []
        origin = "{u.scheme}://{u.netloc}".format(u=urlparse(base_url))

        for path in SENSITIVE_FILE_PATHS:
            test_url = origin + path
            if not self.scope.is_in_scope(test_url):
                continue

            resp = self._get(test_url)
            if resp and resp.status_code == 200 and len(resp.text) > 10:
                findings.append({
                    "url": test_url,
                    "vuln_type": "sensitive_file_exposure",
                    "severity": "high",
                    "title": f"Sensitive File Accessible: `{path}`",
                    "description": (
                        f"The file `{path}` is publicly accessible and returned "
                        f"HTTP 200 with {len(resp.text)} bytes of content."
                    ),
                    "evidence": {
                        "path": path,
                        "status_code": resp.status_code,
                        "content_preview": resp.text[:300],
                    },
                    "request_data": f"GET {test_url}",
                    "response_data": resp.text[:1000],
                    "reproduction": f"1. Navigate to {test_url}\n2. Observe file content in response.",
                    "remediation": (
                        "Block access to sensitive files via web server configuration. "
                        "Remove backup/config files from web root."
                    ),
                    "cvss_score": 7.5,
                })
        return findings

    # ── JWT Weaknesses ─────────────────────────────────────────────────────
    def check_jwt_in_cookies(self, pages: List[Dict]) -> List[Dict]:
        """Detect JWTs in cookies/headers and flag weak 'none' algorithm."""
        findings = []
        for page in pages:
            headers = page.get("headers", {})
            cookies_header = headers.get("Set-Cookie", "")

            jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*'
            matches = re.findall(jwt_pattern, cookies_header + page.get("body", ""))

            for token in matches:
                try:
                    parts = token.split(".")
                    header_b64 = parts[0] + "=="  # pad
                    header_json = base64.urlsafe_b64decode(header_b64).decode("utf-8", errors="ignore")
                    if '"alg":"none"' in header_json or '"alg": "none"' in header_json:
                        findings.append({
                            "url": page["url"],
                            "vuln_type": "jwt_none_algorithm",
                            "severity": "critical",
                            "title": "JWT Using 'none' Algorithm",
                            "description": (
                                "A JWT token was found using the `alg: none` algorithm, "
                                "which means the signature is not verified."
                            ),
                            "evidence": {"token_preview": token[:50] + "...", "header": header_json},
                            "reproduction": (
                                "1. Capture a JWT token from the application.\n"
                                "2. Decode and modify the header to set `alg` to `none`.\n"
                                "3. Remove the signature and replay the token."
                            ),
                            "remediation": "Explicitly reject JWTs with `alg: none`. Use RS256 or HS256.",
                            "cvss_score": 9.1,
                        })
                except Exception:
                    pass
        return findings

    # ── Main Entry ─────────────────────────────────────────────────────────
    def scan_all(self, pages: List[Dict], base_url: str) -> List[Dict]:
        all_findings = []

        if ENABLE_XSS_CHECK:
            print("[ActiveScanner] Checking for XSS...")
            all_findings.extend(self.check_xss(pages))

        if ENABLE_SQLI_CHECK:
            print("[ActiveScanner] Checking for SQL Injection...")
            all_findings.extend(self.check_sqli(pages))

        if ENABLE_OPEN_REDIRECT_CHECK:
            print("[ActiveScanner] Checking for Open Redirects...")
            all_findings.extend(self.check_open_redirect(pages))

        if ENABLE_SENSITIVE_FILES_CHECK:
            print("[ActiveScanner] Checking for Sensitive Files...")
            all_findings.extend(self.check_sensitive_files(base_url))

        if ENABLE_JWT_CHECK:
            print("[ActiveScanner] Checking for JWT Issues...")
            all_findings.extend(self.check_jwt_in_cookies(pages))

        self.findings = all_findings
        print(f"[ActiveScanner] {len(all_findings)} active findings.")
        return all_findings
