"""
modules/burp_importer.py – Parse Burp Suite XML exports and analyze
captured HTTP requests/responses for vulnerability patterns.

How to export from Burp Suite:
  1. Go to Proxy → HTTP History
  2. Select all requests (Ctrl+A)
  3. Right-click → Save items → save as burp_export.xml
  4. Run: py -m bug_bounty_bot.burp_analyzer --file burp_export.xml
"""

import xml.etree.ElementTree as ET
import base64
import re
from urllib.parse import urlparse, parse_qs
from typing import List, Dict


# ── Patterns to flag for manual review ────────────────────────────────────

# Parameters that commonly lead to SSRF
SSRF_PARAMS = [
    "url", "uri", "path", "src", "source", "dest", "destination",
    "redirect", "proxy", "callback", "host", "site", "fetch",
    "load", "file", "request", "endpoint", "target", "link"
]

# Parameters commonly vulnerable to IDOR
IDOR_PARAMS = [
    "id", "user_id", "account_id", "member_id", "card_id",
    "board_id", "list_id", "org_id", "team_id", "token",
    "uid", "pid", "cid", "bid", "oid", "resource_id"
]

# Parameters commonly vulnerable to XSS
XSS_PARAMS = [
    "q", "query", "search", "name", "title", "comment",
    "message", "content", "text", "desc", "description",
    "input", "data", "value", "filter", "tag", "label"
]

# Parameters commonly vulnerable to SQLi
SQLI_PARAMS = [
    "id", "page", "order", "sort", "filter", "limit",
    "offset", "search", "query", "cat", "category"
]

# Parameters that might carry open redirects
REDIRECT_PARAMS = [
    "redirect", "url", "next", "return", "goto", "to",
    "dest", "destination", "continue", "forward", "redirect_uri"
]

# Sensitive endpoints to flag
SENSITIVE_ENDPOINTS = [
    "/admin", "/api/v1", "/api/v2", "/api/v3",
    "/graphql", "/export", "/import", "/backup",
    "/config", "/settings", "/token", "/oauth",
    "/_debug", "/actuator", "/metrics", "/health",
    "/.git", "/.env", "/swagger", "/api-docs"
]

# Interesting response patterns
INTERESTING_RESPONSE_PATTERNS = {
    "api_key":      r'(?i)(api_key|apikey|api-key)["\s:=]+["\']?([A-Za-z0-9_\-]{20,})',
    "jwt_token":    r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*',
    "aws_key":      r'AKIA[0-9A-Z]{16}',
    "private_key":  r'-----BEGIN (RSA|EC|DSA) PRIVATE KEY-----',
    "password_field": r'(?i)"password"\s*:\s*"[^"]+"',
    "email_leak":   r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
    "internal_ip":  r'(10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)',
    "error_stack":  r'(?i)(stack trace|exception|at [a-z]+\.[a-z]+\()',
    "sql_error":    r'(?i)(sql syntax|mysql_fetch|pg_query|sqlite3|ora-\d{5})',
}

# HTTP methods that should have CSRF protection
CSRF_RISKY_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


class BurpRequest:
    """Parsed representation of a single Burp Suite HTTP item."""
    def __init__(self):
        self.url: str = ""
        self.host: str = ""
        self.port: str = ""
        self.protocol: str = ""
        self.method: str = ""
        self.path: str = ""
        self.status_code: int = 0
        self.request_headers: Dict[str, str] = {}
        self.request_body: str = ""
        self.response_headers: Dict[str, str] = {}
        self.response_body: str = ""
        self.params: Dict[str, List[str]] = {}
        self.body_params: Dict[str, str] = {}


def _decode(text: str, is_base64: bool) -> str:
    if not text:
        return ""
    if is_base64:
        try:
            return base64.b64decode(text).decode("utf-8", errors="replace")
        except Exception:
            return text
    return text


def _parse_headers(raw: str) -> Dict[str, str]:
    headers = {}
    for line in raw.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
    return headers


def _parse_body_params(body: str, content_type: str) -> Dict[str, str]:
    params = {}
    if "application/x-www-form-urlencoded" in content_type:
        for part in body.split("&"):
            if "=" in part:
                k, _, v = part.partition("=")
                params[k.strip()] = v.strip()
    elif "application/json" in content_type:
        # Extract top-level keys from JSON roughly
        for match in re.finditer(r'"([^"]+)"\s*:\s*"?([^",}\]]*)', body):
            params[match.group(1)] = match.group(2)
    return params


def parse_burp_xml(file_path: str) -> List[BurpRequest]:
    """Parse a Burp Suite XML export file into a list of BurpRequest objects."""
    items = []
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
    except ET.ParseError as e:
        print(f"[BurpImporter] XML parse error: {e}")
        return items

    for item in root.findall("item"):
        req = BurpRequest()

        req.url      = (item.findtext("url") or "").strip()
        req.host     = (item.findtext("host") or "").strip()
        req.port     = (item.findtext("port") or "").strip()
        req.protocol = (item.findtext("protocol") or "https").strip()
        req.method   = (item.findtext("method") or "GET").strip().upper()
        req.path     = (item.findtext("path") or "/").strip()

        try:
            req.status_code = int(item.findtext("status") or 0)
        except ValueError:
            req.status_code = 0

        # Parse request
        req_elem = item.find("request")
        if req_elem is not None:
            is_b64 = req_elem.get("base64", "false").lower() == "true"
            raw_req = _decode(req_elem.text or "", is_b64)
            parts = raw_req.split("\r\n\r\n", 1)
            req.request_headers = _parse_headers(parts[0])
            req.request_body = parts[1] if len(parts) > 1 else ""
            ct = req.request_headers.get("content-type", "")
            req.body_params = _parse_body_params(req.request_body, ct)

        # Parse response
        resp_elem = item.find("response")
        if resp_elem is not None:
            is_b64 = resp_elem.get("base64", "false").lower() == "true"
            raw_resp = _decode(resp_elem.text or "", is_b64)
            parts = raw_resp.split("\r\n\r\n", 1)
            req.response_headers = _parse_headers(parts[0])
            req.response_body = parts[1] if len(parts) > 1 else ""

        # Parse URL query params
        parsed = urlparse(req.url)
        req.params = parse_qs(parsed.query)

        items.append(req)

    print(f"[BurpImporter] Parsed {len(items)} HTTP items from Burp export.")
    return items


class BurpAnalyzer:
    """
    Analyzes parsed Burp requests for vulnerability patterns.
    Does NOT send any HTTP requests — purely static analysis of captured traffic.
    """

    def __init__(self, scope_domains: List[str] = None):
        self.scope = scope_domains or []
        self.findings: List[Dict] = []

    def _in_scope(self, url: str) -> bool:
        if not self.scope:
            return True
        host = urlparse(url).netloc.lower()
        for domain in self.scope:
            if domain.startswith("*."):
                if host.endswith(domain[2:]):
                    return True
            elif host == domain or host.endswith("." + domain):
                return True
        return False

    # ── SSRF Candidates ────────────────────────────────────────────────────
    def check_ssrf_candidates(self, reqs: List[BurpRequest]) -> List[Dict]:
        findings = []
        for r in reqs:
            if not self._in_scope(r.url):
                continue
            all_params = {**r.params, **{k: [v] for k, v in r.body_params.items()}}
            for param, values in all_params.items():
                if param.lower() in SSRF_PARAMS:
                    val = values[0] if values else ""
                    if any(proto in val.lower() for proto in ["http://", "https://", "ftp://", "file://"]):
                        findings.append({
                            "url": r.url,
                            "vuln_type": "ssrf_candidate",
                            "severity": "high",
                            "title": f"Potential SSRF — parameter `{param}` accepts URLs",
                            "description": (
                                f"The parameter `{param}` at `{r.url}` accepts a URL value "
                                f"(`{val[:80]}`). If the server fetches this URL, it may be "
                                f"vulnerable to Server-Side Request Forgery (SSRF)."
                            ),
                            "evidence": {"param": param, "value": val, "method": r.method},
                            "request_data": f"{r.method} {r.url}\nParam: {param}={val}",
                            "reproduction": (
                                f"1. Send {r.method} request to {r.url}\n"
                                f"2. Set `{param}` to `http://169.254.169.254/latest/meta-data/` (AWS metadata)\n"
                                f"3. Or set to `http://your-server.com/` and check for callback\n"
                                f"4. Observe if the server makes an outbound connection"
                            ),
                            "remediation": (
                                "Validate and whitelist URLs before fetching. Block private IP ranges. "
                                "Use a dedicated outbound proxy that restricts internal network access."
                            ),
                            "cvss_score": 8.6,
                        })
        return findings

    # ── IDOR Candidates ────────────────────────────────────────────────────
    def check_idor_candidates(self, reqs: List[BurpRequest]) -> List[Dict]:
        findings = []
        seen = set()
        for r in reqs:
            if not self._in_scope(r.url):
                continue
            all_params = {**r.params, **{k: [v] for k, v in r.body_params.items()}}
            for param, values in all_params.items():
                if param.lower() in IDOR_PARAMS:
                    val = values[0] if values else ""
                    # Only flag numeric or UUID-like IDs
                    if re.match(r'^[\d]{1,15}$', val) or re.match(
                        r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', val, re.I
                    ):
                        key = (r.path, param)
                        if key not in seen:
                            seen.add(key)
                            findings.append({
                                "url": r.url,
                                "vuln_type": "idor_candidate",
                                "severity": "high",
                                "title": f"Potential IDOR — `{param}` references object ID `{val}`",
                                "description": (
                                    f"The parameter `{param}` at `{r.url}` references a direct "
                                    f"object identifier (`{val}`). Test with another user's ID "
                                    f"to check for unauthorized access."
                                ),
                                "evidence": {"param": param, "value": val, "method": r.method},
                                "request_data": f"{r.method} {r.url}",
                                "reproduction": (
                                    f"1. Log in as User A, note your `{param}` = `{val}`\n"
                                    f"2. Log in as User B in another session\n"
                                    f"3. Send {r.method} {r.url} with User A's `{param}` using User B's session\n"
                                    f"4. If User B can access/modify User A's data → IDOR confirmed"
                                ),
                                "remediation": (
                                    "Implement server-side authorization checks on every object access. "
                                    "Verify that the authenticated user owns or has permission to access the requested resource."
                                ),
                                "cvss_score": 7.5,
                            })
        return findings

    # ── CSRF Candidates ────────────────────────────────────────────────────
    def check_csrf_candidates(self, reqs: List[BurpRequest]) -> List[Dict]:
        findings = []
        seen = set()
        for r in reqs:
            if not self._in_scope(r.url):
                continue
            if r.method not in CSRF_RISKY_METHODS:
                continue

            headers = r.request_headers
            content_type = headers.get("content-type", "").lower()

            # ── Skip JSON APIs — they are CORS-protected by design ──────────
            # A cross-origin form cannot set Content-Type: application/json,
            # triggering a CORS preflight that the server will reject.
            # GraphQL, REST JSON APIs, and batch endpoints are NOT CSRF-exploitable
            # via a standard HTML form-based attack.
            if "application/json" in content_type:
                continue

            # Skip GraphQL endpoints specifically (even if CT is not JSON)
            if "graphql" in r.path.lower():
                continue

            # Skip analytics/tracking/telemetry endpoints (no security impact)
            skip_paths = ["/gasv3/", "/analytics", "/telemetry", "/track",
                          "/metrics", "/onetrust", "/cookie-integrator",
                          "/beacon", "/collect"]
            if any(p in r.path.lower() for p in skip_paths):
                continue

            has_csrf_token = any(
                k in headers for k in ["x-csrf-token", "x-xsrf-token", "csrf-token", "x-requested-with"]
            ) or any(
                k in r.body_params for k in ["csrf_token", "csrfmiddlewaretoken", "_token", "authenticity_token"]
            )

            # Only flag if it looks like a real form-based state-changing action
            is_likely_form = (
                "application/x-www-form-urlencoded" in content_type or
                "multipart/form-data" in content_type or
                (not content_type and r.body_params)  # form with no explicit CT
            )

            if not has_csrf_token and is_likely_form:
                key = (r.method, r.path)
                if key not in seen:
                    seen.add(key)
                    findings.append({
                        "url": r.url,
                        "vuln_type": "csrf_candidate",
                        "severity": "medium",
                        "title": f"Potential Missing CSRF Protection — {r.method} `{r.path}`",
                        "description": (
                            f"A {r.method} form-based request to `{r.url}` was observed without a "
                            f"CSRF token in headers or body. This endpoint accepts "
                            f"`{content_type or 'form-encoded'}` data, meaning it can be triggered "
                            f"by a cross-origin HTML form — a classic CSRF scenario."
                        ),
                        "evidence": {"method": r.method, "content_type": content_type, "headers": list(headers.keys())},
                        "request_data": f"{r.method} {r.url}",
                        "reproduction": (
                            f"1. Create an HTML page with: <form method='{r.method}' action='{r.url}'>\n"
                            f"2. Add hidden fields matching the expected form parameters\n"
                            f"3. Auto-submit on page load\n"
                            f"4. Trick an authenticated user into visiting the page\n"
                            f"5. Observe if the action executes on behalf of the victim"
                        ),
                        "remediation": (
                            "Implement synchronizer token pattern (CSRF tokens) on all form-based endpoints. "
                            "Use SameSite=Strict cookie attribute."
                        ),
                        "cvss_score": 5.4,
                    })
        return findings

    # ── Open Redirect Candidates ───────────────────────────────────────────
    def check_redirect_candidates(self, reqs: List[BurpRequest]) -> List[Dict]:
        findings = []
        for r in reqs:
            if not self._in_scope(r.url):
                continue
            if r.status_code not in (301, 302, 303, 307, 308):
                continue
            all_params = {**r.params, **{k: [v] for k, v in r.body_params.items()}}
            for param in all_params:
                if param.lower() in REDIRECT_PARAMS:
                    val = all_params[param][0] if isinstance(all_params[param], list) else all_params[param]
                    location = r.response_headers.get("location", "")
                    if location and not any(d in location for d in (self.scope or ["example.com"])):
                        findings.append({
                            "url": r.url,
                            "vuln_type": "open_redirect_candidate",
                            "severity": "low",
                            "title": f"Potential Open Redirect via `{param}` parameter",
                            "description": (
                                f"A redirect ({r.status_code}) was observed to `{location}` "
                                f"when parameter `{param}` was set to `{val[:80]}`. "
                                f"Test with external domains to confirm open redirect."
                            ),
                            "evidence": {"param": param, "location": location, "status": r.status_code},
                            "request_data": f"{r.method} {r.url}",
                            "reproduction": (
                                f"1. Navigate to: {r.url} with `{param}=https://evil.com`\n"
                                f"2. Observe redirect to attacker-controlled domain\n"
                                f"3. Note: Verify program policy and reward tiers for Open Redirect findings"
                            ),
                            "remediation": "Validate redirect URLs against an allowlist of trusted domains.",
                            "cvss_score": 4.7,
                        })
                    break
        return findings

    # ── Sensitive Data in Responses ────────────────────────────────────────
    def check_sensitive_data_leaks(self, reqs: List[BurpRequest]) -> List[Dict]:
        findings = []
        seen = set()
        for r in reqs:
            if not self._in_scope(r.url):
                continue
            body = r.response_body[:10000]  # cap to first 10KB
            for leak_type, pattern in INTERESTING_RESPONSE_PATTERNS.items():
                if leak_type == "email_leak":
                    continue  # Too noisy
                matches = re.findall(pattern, body)
                if matches:
                    key = (r.path, leak_type)
                    if key not in seen:
                        seen.add(key)
                        severity = "critical" if leak_type in ("aws_key", "private_key", "jwt_token") else \
                                   "high" if leak_type in ("api_key", "password_field") else "medium"
                        findings.append({
                            "url": r.url,
                            "vuln_type": f"sensitive_data_{leak_type}",
                            "severity": severity,
                            "title": f"Sensitive Data Exposure: {leak_type.replace('_', ' ').title()}",
                            "description": (
                                f"The response from `{r.url}` appears to contain sensitive data "
                                f"matching pattern: `{leak_type}`. "
                                f"Preview: `{str(matches[0])[:100]}`"
                            ),
                            "evidence": {"pattern": leak_type, "preview": str(matches[0])[:150]},
                            "request_data": f"GET {r.url}",
                            "response_data": body[:500],
                            "reproduction": (
                                f"1. Send {r.method} {r.url}\n"
                                f"2. Inspect the response body\n"
                                f"3. Observe {leak_type} in the response"
                            ),
                            "remediation": (
                                "Remove sensitive data from API responses. "
                                "Never expose credentials, tokens, or keys in HTTP responses."
                            ),
                            "cvss_score": {"critical": 9.1, "high": 7.5, "medium": 5.3}.get(severity, 5.0),
                        })
        return findings

    # ── Sensitive Endpoints ────────────────────────────────────────────────
    def check_sensitive_endpoints(self, reqs: List[BurpRequest]) -> List[Dict]:
        findings = []
        seen = set()
        for r in reqs:
            if not self._in_scope(r.url):
                continue
            for endpoint in SENSITIVE_ENDPOINTS:
                if r.path.lower().startswith(endpoint) and r.status_code == 200:
                    if r.path not in seen:
                        seen.add(r.path)
                        findings.append({
                            "url": r.url,
                            "vuln_type": "sensitive_endpoint_accessible",
                            "severity": "medium",
                            "title": f"Sensitive Endpoint Accessible: `{r.path}`",
                            "description": (
                                f"The endpoint `{r.url}` returned HTTP 200. "
                                f"This path (`{endpoint}`) typically exposes sensitive functionality "
                                f"or information."
                            ),
                            "evidence": {"path": r.path, "status": r.status_code},
                            "request_data": f"{r.method} {r.url}",
                            "reproduction": f"1. Send {r.method} {r.url}\n2. Observe HTTP 200 response",
                            "remediation": "Restrict access to administrative and debug endpoints. Require authentication.",
                            "cvss_score": 5.3,
                        })
        return findings

    # ── XSS Parameter Candidates ───────────────────────────────────────────
    def check_xss_candidates(self, reqs: List[BurpRequest]) -> List[Dict]:
        findings = []
        seen = set()
        for r in reqs:
            if not self._in_scope(r.url):
                continue
            all_params = {**r.params, **{k: [v] for k, v in r.body_params.items()}}
            # Check if params are reflected in response
            for param, values in all_params.items():
                val = values[0] if isinstance(values, list) else values
                if val and len(val) > 2 and val in r.response_body:
                    key = (r.path, param)
                    if key not in seen and param.lower() in XSS_PARAMS:
                        seen.add(key)
                        findings.append({
                            "url": r.url,
                            "vuln_type": "xss_candidate",
                            "severity": "high",
                            "title": f"Potential Reflected XSS — parameter `{param}` value reflected in response",
                            "description": (
                                f"The value of `{param}` (`{val[:60]}`) is reflected verbatim in the "
                                f"HTTP response from `{r.url}`. Test with XSS payloads to confirm."
                            ),
                            "evidence": {"param": param, "reflected_value": val[:100]},
                            "request_data": f"{r.method} {r.url}",
                            "reproduction": (
                                f"1. Send {r.method} {r.url}\n"
                                f"2. Set `{param}` = `<script>alert(1)</script>`\n"
                                f"3. Check if payload is reflected unencoded in the response\n"
                                f"4. Note: Check target Content-Security-Policy (CSP) for potential bypasses"
                            ),
                            "remediation": (
                                "HTML-encode all user-supplied input before reflecting it in responses. "
                                "Implement and enforce a strict Content-Security-Policy."
                            ),
                            "cvss_score": 6.1,
                        })
        return findings

    # ── Main Analysis ──────────────────────────────────────────────────────
    def analyze(self, reqs: List[BurpRequest]) -> List[Dict]:
        print(f"[BurpAnalyzer] Analyzing {len(reqs)} captured requests...")
        all_findings = []

        print("  → Checking for SSRF candidates...")
        all_findings.extend(self.check_ssrf_candidates(reqs))

        print("  → Checking for IDOR candidates...")
        all_findings.extend(self.check_idor_candidates(reqs))

        print("  → Checking for CSRF candidates...")
        all_findings.extend(self.check_csrf_candidates(reqs))

        print("  → Checking for open redirect candidates...")
        all_findings.extend(self.check_redirect_candidates(reqs))

        print("  → Checking for sensitive data leaks in responses...")
        all_findings.extend(self.check_sensitive_data_leaks(reqs))

        print("  → Checking for sensitive endpoints...")
        all_findings.extend(self.check_sensitive_endpoints(reqs))

        print("  → Checking for XSS candidates...")
        all_findings.extend(self.check_xss_candidates(reqs))

        print(f"[BurpAnalyzer] Found {len(all_findings)} candidate(s) for review.")
        return all_findings
