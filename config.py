"""
config.py – Central configuration for the Bug Bounty Bot.
Set your API keys and scanning preferences here.
"""

import os
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# ── LLM API (Google Gemini or OpenRouter) ─────────────────────────────────
# Supported providers: "gemini" or "openrouter"
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "gemini")

# Google Gemini settings
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = "gemini-3.6-flash"

# OpenRouter settings (fallback)
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
CLAUDE_MODEL = "anthropic/claude-sonnet-4.5"

# ── Database ──────────────────────────────────────────────────────────────
DB_PATH = "bug_bounty_bot/database/findings.db"

# ── Crawler settings ──────────────────────────────────────────────────────
MAX_CRAWL_DEPTH = 3          # How deep to follow links
MAX_PAGES_PER_TARGET = 100   # Hard cap to prevent runaway crawling
REQUEST_TIMEOUT = 10         # Seconds per HTTP request
REQUEST_DELAY = 0.5          # Polite delay between requests (seconds)
USER_AGENT = (
    "BugBountyBot/1.0 (authorized security research; "
    "contact: your@email.com)"
)

# ── Active scanning ────────────────────────────────────────────────────────
ENABLE_XSS_CHECK = True
ENABLE_SQLI_CHECK = True
ENABLE_OPEN_REDIRECT_CHECK = True
ENABLE_IDOR_CHECK = True
ENABLE_SENSITIVE_FILES_CHECK = True
ENABLE_HEADER_ANALYSIS = True
ENABLE_JWT_CHECK = True

# ── Severity levels ────────────────────────────────────────────────────────
SEVERITY_LEVELS = ["critical", "high", "medium", "low", "info"]

# ── Reports ────────────────────────────────────────────────────────────────
REPORTS_DIR = "bug_bounty_bot/reports"

# ── Targets file ──────────────────────────────────────────────────────────
TARGETS_FILE = "bug_bounty_bot/targets/targets.json"
