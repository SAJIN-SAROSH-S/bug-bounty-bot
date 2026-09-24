"""
modules/deduplicator.py – Remove duplicate findings before reporting.
Two findings are duplicates if they share the same vuln_type and URL.
"""

from typing import List, Dict


def deduplicate(findings: List[Dict]) -> List[Dict]:
    seen = set()
    unique = []
    for f in findings:
        key = (f.get("vuln_type", ""), f.get("url", ""), f.get("title", ""))
        if key not in seen:
            seen.add(key)
            unique.append(f)
    removed = len(findings) - len(unique)
    print(f"[Deduplicator] {len(findings)} findings → {len(unique)} unique ({removed} removed).")
    return unique
