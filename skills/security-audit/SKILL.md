---
name: security-audit
description: >
  Perform a professional security and QA audit of a web application or codebase.
  Use when asked to audit, review, or security-test a GitHub repo, live URL, or source files.
  Produces an enterprise-grade report with CVSS scores, live PoC verification (curl tests against
  production), root cause with exact file and line, and remediation code.
  Covers OWASP Top 10, hardcoded secrets, broken access control, missing auth, input validation.
  Unique: every Critical and High finding is verified live against the running app before reporting.
---

# Security Audit

## Workflow

### Phase 1: Reconnaissance
1. Clone or read the repository; identify stack (language, framework, deployment)
2. Map the attack surface: all HTTP endpoints, API routes, public URLs
3. Identify entry points: user input, file upload, auth flows, API keys in code
4. Note dependencies: `package.json`, `requirements.txt`, `go.mod`, etc.

### Phase 2: Static Analysis
Read source files systematically. For each file, apply:
- See `references/owasp-patterns.md` for OWASP Top 10 patterns per language
- Flag secrets with regex patterns in `references/owasp-patterns.md`
- Check auth middleware presence on every route
- Note missing security headers, rate limiting, input validation

**Input validation checklist (check every field that accepts user input):**
- URL fields: only `http://` and `https://` should be accepted. Flag `javascript:`, `data:`, `file:`, `//` schemes
- Numeric fields: negative values, zero, overflow (`2147483648`), float precision
- String fields: `<script>`, `<img onerror=>`, `"`, `'`, `{{7*7}}` (SSTI)
- All stored user content: verify it's HTML-escaped on render, not stored raw

**Auth/access checklist:**
- Every endpoint accessible without auth token?
- Forms rendered to unauthenticated users (check both SSR HTML and JS-rendered state)?
- Approval workflows: is status `approved` immediately, or `pending` pending review?
- Self-referencing: can a user act on their own resource (review own product, join own affiliate)?

### Phase 3: Live Verification (critical differentiator)
For every Critical and High finding — **verify against the running app**.

**Strict rules (one violation = reputation gone):**
- Only `GET` and `HEAD` requests for read-only verification. `POST`/`PUT` only if needed to verify write-path vulns, and only with throwaway/test data
- Timeout: `--max-time 10` on every curl request
- Log every request before sending: `[PoC] GET https://target.app/api/endpoint`
- **Clean up** any test data created during verification (delete test records, revoke test tokens)
- Never modify or delete real user data
- If in doubt about safety — mark as Static (code only), do not test live

**Unauthenticated flow verification — do both:**
```bash
# 1. API level (curl without token)
curl -s --max-time 10 https://target.app/api/endpoint

# 2. Browser level (headless snapshot)
# Navigate to the page without logging in
# Check: does the SSR HTML already contain sensitive data?
# Check: does the page render a form that fails silently on submit?
```

**Environment config leak check:**
```bash
# Test with invalid/expired identifiers — where does the fallback redirect go?
curl -sI "https://target.app/api/click?ref=invalid-xyz" | grep -i location
# Red flag: Location: https://localhost:* or http://127.0.0.1:*
```

```bash
# Example: verify unauthenticated endpoint
curl -s --max-time 10 https://target.app/api/endpoint
# Log before running: [PoC] GET https://target.app/api/endpoint
```
- Document: HTTP method, URL, response status, response snippet (max 200 chars)

### Phase 4: Structured Output
Before writing the report, output findings as JSON (for auto-processing):
```json
{
  "target": "repo-name",
  "date": "YYYY-MM-DD",
  "findings": [
    {
      "id": "C-01",
      "title": "Finding title",
      "severity": "Critical",
      "cvss": 9.1,
      "status": "Confirmed",
      "location": "path/to/file.ts:42",
      "owasp": "A01"
    }
  ],
  "summary": { "critical": 1, "high": 2, "medium": 3, "low": 1 }
}
```
Then render full human report. See `references/report-format.md` for template.

Quick structure:
1. Executive Summary (3–5 sentences, non-technical)
2. Finding Distribution table
3. Findings: Critical → High → Medium → Low
4. Positive Observations
5. Remediation Priority Table

Each finding must include:
- Severity + CVSS score (see `references/severity-model.md`)
- File path + line number
- Live PoC output (for Critical/High)
- Root cause explanation
- Remediation code snippet

## Rules
- English only for all reports
- No speculative findings — evidence required for every issue
- Live testing: `--max-time 10` on every request, log before sending, clean up test data
- CVSS scores required for Critical and High
- Remediation must include working code, not just description
- Mark every finding as: Confirmed (live-tested) or Static (code only)
- **One finding = one issue** — never bundle multiple bugs; each gets its own title, PoC, CVSS
- **Security findings stay private** (client DM/email only) until client confirms the fix is deployed. Never file public GitHub issues for security vulns without explicit client approval
- Update this skill after each real audit based on what actually worked

## Changelog
- **1.1.0** — Added input validation checklist (URL schemes, negatives, SSTI), unauthenticated flow verification (API + browser), environment config leak check, approval workflow testing, disclosure rules, "one finding = one issue" rule
- **1.0.0** — Initial release

---

## GitHub Integration (Optional)

After the audit completes, you can optionally create GitHub issues from findings:

### Script Location
```
~/.openclaw/workspace/scripts/create-security-issues.js
~/.openclaw/workspace/scripts/create-security-issues.sh
```

### Usage

**Ask Igor first:** "Створити issue в репозиторії клієнта?"

If yes:
```bash
# Node.js version
node scripts/create-security-issues.js owner/repo findings.json

# Or via stdin
cat findings.json | node scripts/create-security-issues.js owner/repo -

# Bash version (requires findings as JSON string)
./scripts/create-security-issues.sh "owner/repo" '{"findings":[...]}'
```

### Issue Format

Each issue includes:
- Title: `[CRITICAL/HIGH/MEDIUM/LOW] Finding title`
- Labels: `security`, `Critical`/`High`/`Medium`/`Low`
- Body: CVSS, location, PoC, root cause, remediation

### Important

- **Security findings are sensitive** — never create issues without explicit client approval
- Use the JSON output from Phase 4 as input
- The script automatically labels issues by severity
