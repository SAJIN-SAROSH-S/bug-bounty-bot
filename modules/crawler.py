"""
modules/crawler.py – Polite BFS web crawler.
Discovers pages and endpoints within scope.
"""

import time
import re
from collections import deque
from urllib.parse import urljoin, urlparse, urlunparse
from typing import Set, List, Dict

import requests
from bs4 import BeautifulSoup

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from bug_bounty_bot.config import (
    MAX_CRAWL_DEPTH, MAX_PAGES_PER_TARGET,
    REQUEST_TIMEOUT, REQUEST_DELAY, USER_AGENT
)
from bug_bounty_bot.modules.scope_checker import ScopeChecker


class Crawler:
    def __init__(self, scope_checker: ScopeChecker):
        self.scope = scope_checker
        self.session = requests.Session()
        self.session.headers["User-Agent"] = USER_AGENT
        self.visited: Set[str] = set()
        self.pages: List[Dict] = []   # {url, status_code, headers, body, forms, links}

    def _normalize(self, url: str) -> str:
        """Remove fragments and trailing slashes for deduplication."""
        p = urlparse(url)
        return urlunparse(p._replace(fragment="")).rstrip("/")

    def _extract_links(self, base_url: str, html: str) -> List[str]:
        soup = BeautifulSoup(html, "html.parser")
        links = []
        for tag in soup.find_all("a", href=True):
            href = tag["href"].strip()
            full = urljoin(base_url, href)
            links.append(self._normalize(full))
        return links

    def _extract_forms(self, base_url: str, html: str) -> List[Dict]:
        soup = BeautifulSoup(html, "html.parser")
        forms = []
        for form in soup.find_all("form"):
            action = urljoin(base_url, form.get("action", ""))
            method = form.get("method", "get").lower()
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                inputs.append({
                    "name": inp.get("name", ""),
                    "type": inp.get("type", "text"),
                    "value": inp.get("value", ""),
                })
            forms.append({"action": action, "method": method, "inputs": inputs})
        return forms

    def _extract_js_endpoints(self, html: str) -> List[str]:
        """Simple regex to find API endpoints in JS."""
        return re.findall(r'["\'](/api/[^"\']+)["\']', html)

    def crawl(self, start_url: str) -> List[Dict]:
        """BFS crawl from start_url. Returns list of page dicts."""
        queue = deque([(start_url, 0)])
        self.visited.add(self._normalize(start_url))

        while queue and len(self.pages) < MAX_PAGES_PER_TARGET:
            url, depth = queue.popleft()

            if depth > MAX_CRAWL_DEPTH:
                continue
            if not self.scope.is_in_scope(url):
                continue

            try:
                print(f"  [Crawler] GET {url}")
                resp = self.session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
                time.sleep(REQUEST_DELAY)

                content_type = resp.headers.get("Content-Type", "")
                html = resp.text if "html" in content_type else ""

                page = {
                    "url": url,
                    "status_code": resp.status_code,
                    "headers": dict(resp.headers),
                    "body": resp.text[:50_000],  # cap body size
                    "forms": self._extract_forms(url, html),
                    "links": [],
                    "js_endpoints": self._extract_js_endpoints(html),
                }

                links = self._extract_links(url, html)
                in_scope_links = self.scope.filter_urls(links)
                page["links"] = in_scope_links
                self.pages.append(page)

                for link in in_scope_links:
                    norm = self._normalize(link)
                    if norm not in self.visited:
                        self.visited.add(norm)
                        queue.append((link, depth + 1))

            except requests.RequestException as e:
                print(f"  [Crawler] ERROR {url}: {e}")

        print(f"[Crawler] Crawled {len(self.pages)} pages.")
        return self.pages
