"""
modules/target_manager.py – Load and manage bug bounty targets.
Reads from targets/targets.json (can be extended to pull from
Bugcrowd / HackerOne APIs).
"""

import json
from pathlib import Path
from typing import List, Dict

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from bug_bounty_bot.config import TARGETS_FILE


def load_targets() -> List[Dict]:
    """Load all programs from the targets JSON file."""
    path = Path(TARGETS_FILE)
    if not path.exists():
        raise FileNotFoundError(f"Targets file not found: {TARGETS_FILE}")
    with open(path) as f:
        data = json.load(f)
    programs = data.get("programs", [])
    print(f"[TargetManager] Loaded {len(programs)} program(s).")
    return programs


def select_program(programs: List[Dict]) -> Dict:
    """Interactive CLI selection when multiple programs exist."""
    if len(programs) == 1:
        return programs[0]

    print("\nAvailable Bug Bounty Programs:")
    for i, p in enumerate(programs):
        print(f"  [{i+1}] {p['name']} ({p['platform']})")
    while True:
        try:
            choice = int(input("\nSelect program number: ")) - 1
            if 0 <= choice < len(programs):
                return programs[choice]
        except (ValueError, KeyboardInterrupt):
            pass
        print("Invalid choice. Try again.")


def get_all_start_urls(program: Dict) -> List[str]:
    """Return the list of start URLs for a program."""
    return program.get("start_urls", [])
