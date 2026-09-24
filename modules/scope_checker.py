"""
modules/scope_checker.py – Validate that a URL is within the
authorized scope of the current bug bounty program.
"""

import fnmatch
from urllib.parse import urlparse
from typing import Dict


class ScopeChecker:
    def __init__(self, program: Dict):
        self.in_scope: list = program.get("in_scope", [])
        self.out_of_scope: list = program.get("out_of_scope", [])

    def _hostname(self, url: str) -> str:
        return urlparse(url).netloc.lower()

    def _matches_any(self, hostname: str, patterns: list) -> bool:
        for pattern in patterns:
            # Strip scheme if present in the pattern
            pattern = pattern.replace("https://", "").replace("http://", "")
            if fnmatch.fnmatch(hostname, pattern):
                return True
        return False

    def is_in_scope(self, url: str) -> bool:
        """Return True only if URL is in scope and NOT out-of-scope."""
        try:
            hostname = self._hostname(url)
            if not hostname:
                return False
            # Must match an in-scope pattern
            if not self._matches_any(hostname, self.in_scope):
                return False
            # Must NOT match any out-of-scope pattern
            if self._matches_any(hostname, self.out_of_scope):
                return False
            return True
        except Exception:
            return False

    def filter_urls(self, urls: list) -> list:
        """Return only in-scope URLs from a list."""
        return [u for u in urls if self.is_in_scope(u)]
