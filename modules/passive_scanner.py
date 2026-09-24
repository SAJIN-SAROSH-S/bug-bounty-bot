"""
modules/passive_scanner.py – No-request passive analysis.
Analyzes already-fetched pages for security misconfigurations.
"""

from typing import List, Dict


# Security headers that should be present
REQUIRED_HEADERS = {
    "Strict-Transport-Security": "high",
    "Content-Security-Policy": "medium",
    "X-Content-Type-Options": "low",
    "X-Frame-Options": "medium",
    "Referrer-Policy": "low",
    "Permissions-Policy": "info",
}

SENSITIVE_FILE_PATHS = [
    "/.env", "/.git/HEAD", "/.git/config",
    "/backup.zip", "/backup.tar.gz", "/db.sql",
    "/wp-config.php.bak", "/.DS_Store",
    "/config.json", "/secrets.json", "/credentials.json",
    "/phpinfo.php", "/.htaccess",
    "/api/swagger.json", "/api/openapi.json",
    "/actuator/env", "/actuator/health",
]

TECH_SIGNATURES = {
    "WordPress": ["wp-content", "wp-includes"],
    "Django": ["csrfmiddlewaretoken"],
    "Laravel": ["laravel_session"],
    "React": ["react", "__NEXT_DATA__"],
    "jQuery": ["jquery"],
}


class PassiveScanner:
    def __init__(self):
        self.findings: List[Dict] = []

    def scan_headers(self, page: Dict) -> List[Dict]:
        findings = []
        headers = {k.lower(): v for k, v in page.get("headers", {}).items()}

        for header, severity in REQUIRED_HEADERS.items():
            if header.lower() not in headers:
                findings.append({
                    "url": page["url"],
                    "vuln_type": "missing_security_header",
                    "severity": severity,
                    "title": f"Missing Security Header: {header}",
                    "description": (
                        f"The response from {page['url']} is missing the "
                        f"`{header}` HTTP security header."
                    ),
                    "evidence": {"missing_header": header, "present_headers": list(headers.keys())},
                    "reproduction": f"Send GET {page['url']} and inspect response headers.",
                    "remediation": f"Add the `{header}` header to all HTTP responses.",
                })

        # Check for server version disclosure
        server = headers.get("server", "")
        x_powered = headers.get("x-powered-by", "")
        for val, name in [(server, "Server"), (x_powered, "X-Powered-By")]:
            if any(char.isdigit() for char in val):  # version number present
                findings.append({
                    "url": page["url"],
                    "vuln_type": "version_disclosure",
                    "severity": "info",
                    "title": f"Version Disclosure via {name} Header",
                    "description": f"The `{name}` header reveals: `{val}`",
                    "evidence": {"header": name, "value": val},
                    "reproduction": f"GET {page['url']} → check {name} header.",
                    "remediation": "Remove or sanitize the version from this header.",
                })

        return findings

    def scan_sensitive_files(self, pages: List[Dict], base_url: str) -> List[Dict]:
        """
        Return a list of paths to check (actual HTTP requests made in active scanner).
        This passive method just flags any fetched page that looks like a sensitive file.
        """
        findings = []
        sensitive_names = [p.lstrip("/") for p in SENSITIVE_FILE_PATHS]

        for page in pages:
            path = page["url"].split("?")[0].rstrip("/").split("/")[-1]
            if any(path in s for s in sensitive_names):
                if page["status_code"] == 200:
                    findings.append({
                        "url": page["url"],
                        "vuln_type": "sensitive_file_exposure",
                        "severity": "high",
                        "title": f"Sensitive File Exposed: {path}",
                        "description": (
                            f"A potentially sensitive file is publicly accessible at "
                            f"{page['url']} (HTTP {page['status_code']})."
                        ),
                        "evidence": {"status_code": page["status_code"], "body_preview": page["body"][:500]},
                        "reproduction": f"GET {page['url']} returns HTTP 200 with content.",
                        "remediation": "Restrict access to this file via server configuration.",
                    })
        return findings

    def detect_technologies(self, pages: List[Dict]) -> Dict[str, bool]:
        """Passive technology fingerprinting."""
        detected = {}
        for page in pages:
            body = page.get("body", "").lower()
            for tech, sigs in TECH_SIGNATURES.items():
                if any(sig.lower() in body for sig in sigs):
                    detected[tech] = True
        return detected

    def scan_all(self, pages: List[Dict]) -> List[Dict]:
        all_findings = []
        for page in pages:
            all_findings.extend(self.scan_headers(page))
        if pages:
            base = pages[0]["url"]
            all_findings.extend(self.scan_sensitive_files(pages, base))
        self.findings = all_findings
        print(f"[PassiveScanner] {len(all_findings)} passive findings.")
        return all_findings
