# 🔍 Bug Bounty Bot

An automated, **human-supervised** security research tool for bug bounty programs.

> ⚠️ **Authorization Required**: Only test against targets explicitly listed in a bug bounty program you're enrolled in, or systems you own/have written permission to test.

---

## Architecture

```
main.py (Orchestrator)
 ├── target_manager.py    → Load targets from targets/targets.json
 ├── scope_checker.py     → Validate every URL is in-scope
 ├── crawler.py           → BFS web crawl (respects rate limits)
 ├── passive_scanner.py   → Headers, version disclosure, sensitive files
 ├── active_scanner.py    → XSS, SQLi, Open Redirect, JWT, file exposure
 ├── deduplicator.py      → Remove duplicate findings
 ├── report_writer.py     → Claude AI generates professional reports
 ├── human_review.py      → YOU review and approve each finding
 └── submission.py        → Submit to HackerOne / Bugcrowd
```

---

## Setup

### 1. Install dependencies
```bash
py -m pip install -r requirements.txt
```

### 2. Add your Anthropic API key
Edit `config.py`:
```python
ANTHROPIC_API_KEY = "sk-ant-..."
```
Or set it as an environment variable:
```bash
set ANTHROPIC_API_KEY=sk-ant-...
```

### 3. Configure your target
Edit `targets/targets.json`:
```json
{
  "programs": [
    {
      "name": "My Bug Bounty Target",
      "platform": "hackerone",
      "in_scope": ["*.example.com"],
      "out_of_scope": ["blog.example.com"],
      "start_urls": ["https://app.example.com"]
    }
  ]
}
```

### 4. Run
```bash
py -m bug_bounty_bot.main
```

---

## Vulnerability Checks

| Check | Type | Severity |
|---|---|---|
| Missing security headers | Passive | Low–High |
| Version disclosure | Passive | Info |
| Sensitive file exposure | Active | High |
| Reflected XSS | Active | High |
| SQL Injection (error-based) | Active | Critical |
| Open Redirect | Active | Medium |
| JWT `none` algorithm | Active | Critical |

---

## Workflow

```
1. Load authorized target
2. Validate scope (every URL checked before request)
3. Crawl pages & discover endpoints
4. Passive scan (no extra requests)
5. Active scan (safe, non-destructive payloads)
6. Deduplicate findings
7. Claude generates professional report drafts
8. 🔴 YOU review and approve each finding
9. Submit to platform (HackerOne / Bugcrowd)
```

---

## Ethics & Legal

- Only test **in-scope targets** from authorized programs
- Do not test payment systems, delete data, or cause service disruption
- Human review is **mandatory** before any submission
- AI-generated reports must be manually validated (per Bugcrowd policy)

---

## Extending the Bot

- Add new checks in `modules/active_scanner.py`
- Add new passive fingerprints in `modules/passive_scanner.py`
- Connect to Bugcrowd/HackerOne APIs in `modules/submission.py`
- Add Playwright-based checks for JS-heavy SPAs
