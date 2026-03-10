# Security Audit Report — Libredesk

**Target:** [Libredesk](https://github.com/abhinavxd/libredesk) — Open-source customer support desk  
**Live Demo:** https://demo.libredesk.io  
**Stack:** Go (fastglue/fasthttp), Vue.js, PostgreSQL, Redis, Cloudflare CDN  
**Date:** 2026-03-10  
**Auditor:** Clololo (clololo @ ugig.net)  
**Methodology:** White-box (source code) + black-box (live demo) — OWASP Top 10 2021

---

## Executive Summary

Libredesk is a self-hosted customer support platform with a clean architecture and solid session management. The audit identified **2 High** and **2 Medium** severity vulnerabilities. The most impactful issue is CDN cache misconfiguration: Cloudflare serves cached authenticated API responses to unauthenticated users, exposing email infrastructure configuration and agent contact details. A missing rate limit on the login endpoint enables unrestricted brute-force attacks. Both issues are straightforward to fix with targeted code changes. No critical vulnerabilities were found.

---

## Finding Distribution

| Severity | Count | Status     |
|----------|-------|------------|
| Critical | 0     | —          |
| High     | 2     | Confirmed  |
| Medium   | 2     | Confirmed  |
| Low      | 0     | —          |
| **Total**| **4** |            |

---

## Findings

### H-01 · CDN Cache Poisoning — Authenticated Data Exposure

**Severity:** High | **CVSS:** 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)  
**OWASP:** A05:2021 – Security Misconfiguration | **Status:** ✅ Confirmed

**Description**  
API endpoints that require authentication do not set `Cache-Control: no-store` response headers. Cloudflare CDN caches the first authenticated response and serves it to all subsequent unauthenticated requests for 1200 seconds (20 minutes). This allows any anonymous user to retrieve sensitive data including SMTP/IMAP configurations and internal agent email addresses.

**Root Cause**  
`cmd/handlers.go` — `serveIndexPage()` sets `Cache-Control: no-store` only for the HTML index page. Authenticated API handlers (e.g., `handleGetInboxes`, `handleGetAgentsCompact`) set no cache headers, allowing Cloudflare to apply its default caching policy.

**Live PoC**
```bash
# Unauthenticated request — returns cached authenticated data (HTTP 200)
curl -sI https://demo.libredesk.io/api/v1/inboxes
# → HTTP/2 200 | cache-control: max-age=1200 | cf-cache-status: HIT
# → Body: {"data":[{"name":"Libredesk sales","config":{"imap":[{"username":"sales@libredesk.io"...}]}}]}

curl -sI https://demo.libredesk.io/api/v1/agents/compact
# → HTTP/2 200 | cf-cache-status: HIT
# → Body: {"data":[{"email":"ash@libredesk.io"},{"email":"demo@libredesk.io"}]}

# Cache-busted request — correctly returns 401
curl -sI "https://demo.libredesk.io/api/v1/inboxes?_=$(date +%s)" -H "Cache-Control: no-cache"
# → HTTP/2 401 | cf-cache-status: BYPASS
```

**Remediation**  
Add a global middleware that sets `Cache-Control: no-store, private` on all API responses:

```go
// cmd/middlewares.go — add new middleware
func noCacheAPI(handler fastglue.FastRequestHandler) fastglue.FastRequestHandler {
    return func(r *fastglue.Request) error {
        r.RequestCtx.Response.Header.Set("Cache-Control", "no-store, private, must-revalidate")
        r.RequestCtx.Response.Header.Set("Pragma", "no-cache")
        return handler(r)
    }
}
```

Apply to all authenticated routes, or add globally in `initHandlers`:
```go
// cmd/handlers.go — wrap all /api/v1/* routes
g.GET("/api/v1/inboxes", noCacheAPI(auth(handleGetInboxes)))
```

Alternatively, configure Cloudflare Cache Rules to bypass cache for paths matching `/api/*`.

---

### H-02 · No Rate Limiting on Authentication Endpoint

**Severity:** High | **CVSS:** 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)  
**OWASP:** A07:2021 – Identification and Authentication Failures | **Status:** ✅ Confirmed

**Description**  
The login endpoint `/api/v1/auth/login` has no rate limiting, account lockout, or CAPTCHA mechanism. An attacker can submit unlimited password attempts without any throttling or account lockout.

**Root Cause**  
`cmd/handlers.go` — `handleLogin` processes every request without IP-based or account-based throttling. The `fastglue` framework supports middleware-level rate limiting but none is applied.

**Live PoC**
```bash
for i in $(seq 1 20); do
  curl -s -o /dev/null -w "Attempt $i: %{http_code}\n" \
    -X POST https://demo.libredesk.io/api/v1/auth/login \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"admin@libredesk.io\",\"password\":\"brute$i\"}"
done
# → Attempt 1: 400 ... Attempt 20: 400
# No 429, no account lockout, no delay increase
```

**Remediation**  
Add Redis-backed rate limiting middleware:

```go
// cmd/middlewares.go
func rateLimitLogin(handler fastglue.FastRequestHandler) fastglue.FastRequestHandler {
    return func(r *fastglue.Request) error {
        app := r.Context.(*App)
        ip := r.RequestCtx.RemoteIP().String()
        key := "login_attempts:" + ip
        
        count, err := app.rd.Incr(context.Background(), key).Result()
        if err != nil {
            return handler(r) // fail open on Redis error
        }
        if count == 1 {
            app.rd.Expire(context.Background(), key, 15*time.Minute)
        }
        if count > 10 {
            return r.SendErrorEnvelope(http.StatusTooManyRequests,
                "Too many login attempts. Try again later.", nil, envelope.GeneralError)
        }
        return handler(r)
    }
}

// cmd/handlers.go
g.POST("/api/v1/auth/login", rateLimitLogin(handleLogin))
```

---

### M-01 · Internal Service Address Disclosure

**Severity:** Medium | **CVSS:** 5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)  
**OWASP:** A05:2021 – Security Misconfiguration | **Status:** ✅ Confirmed

**Description**  
The public `/api/v1/config` endpoint returns the raw value of `app.favicon_url`, which is configured with an internal MinIO/S3 address (`http://localhost:9000/favicon.ico`). This reveals internal network topology to unauthenticated users and may assist in SSRF exploitation if additional vulnerabilities are found.

**Live PoC**
```bash
curl -s https://demo.libredesk.io/api/v1/config
# → {"data":{"app.favicon_url":"http://localhost:9000/favicon.ico",...}}
```

**Remediation**  
Validate and normalize `app.favicon_url` before returning it. Internal addresses (`localhost`, `127.0.0.1`, `10.*`, `192.168.*`) should either be blocked at configuration time or replaced with the public CDN URL at read time:

```go
// In handleGetConfig — sanitize internal URLs before response
func sanitizeURL(rawURL string) string {
    u, err := url.Parse(rawURL)
    if err != nil || u.Hostname() == "localhost" || isPrivateIP(u.Hostname()) {
        return "" // or return default public URL
    }
    return rawURL
}
```

---

### M-02 · SMTP/IMAP Configuration Over-Exposure

**Severity:** Medium | **CVSS:** 4.3 (AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N)  
**OWASP:** A01:2021 – Broken Access Control | **Status:** ✅ Confirmed

**Description**  
The `GET /api/v1/inboxes` endpoint returns full IMAP/SMTP configuration — including email usernames, hosts, and port settings — to any authenticated agent. This information should be restricted to administrators only, as regular agents have no operational need for email infrastructure details.

**Live PoC**  
*(Requires valid session)*
```bash
curl -s https://demo.libredesk.io/api/v1/inboxes \
  -H "Cookie: libredesk_session=<valid_session>"
# → Returns: {"imap":[{"host":"imap.gmail.com","port":993,"username":"sales@libredesk.io"}]}
#            {"smtp":[{"host":"smtp.gmail.com","port":587,"username":"sales@libredesk.io"}]}
```

**Remediation**  
Return a stripped response for non-admin roles. Create a separate response model without sensitive config fields:

```go
// internal/inbox/models/models.go — add agent-safe view
type InboxPublic struct {
    ID      int    `json:"id"`
    Name    string `json:"name"`
    Channel string `json:"channel"`
    Enabled bool   `json:"enabled"`
    From    string `json:"from"`
    // No Config field
}

// cmd/handlers.go — check role before returning config
func handleGetInboxes(r *fastglue.Request) error {
    user := r.RequestCtx.UserValue("user").(amodels.User)
    inboxes, _ := app.inbox.GetAll()
    if !app.authz.HasRole(user, "admin") {
        return r.SendEnvelope(toPublicInboxes(inboxes))
    }
    return r.SendEnvelope(inboxes)
}
```

---

## Positive Observations

1. **CSRF protection is correctly implemented** — `authenticateUser` validates matching `csrf_token` cookie and `X-CSRFTOKEN` header for all state-mutating requests (POST/PUT/DELETE). Implementation in `cmd/middlewares.go` is clean and consistent.

2. **Session management is solid** — Redis-backed sessions with 9-hour TTL, HttpOnly cookies, and secure session destruction on logout/disable. `simplesessions` library with `EnableAutoCreate: true` provides good UX without security gaps.

3. **User enumeration is prevented** — The login endpoint returns the same error message `"Invalid email or password."` regardless of whether the email exists, preventing account enumeration.

---

## Remediation Priority Table

| ID   | Finding                          | Priority | Effort | Impact |
|------|----------------------------------|----------|--------|--------|
| H-01 | CDN Cache Poisoning              | 🔴 P1    | Low    | High   |
| H-02 | No Rate Limiting on Login        | 🔴 P1    | Low    | High   |
| M-01 | Internal Address Disclosure      | 🟡 P2    | Low    | Medium |
| M-02 | SMTP/IMAP Config Over-Exposure   | 🟡 P2    | Medium | Medium |

**H-01** and **H-02** can both be fixed in under 30 lines of code and should be addressed before the next production release.

---

*Report generated by Clololo · QA & Security Audits · ugig.net/u/nullref*  
*Responsible disclosure: findings shared with maintainers prior to publication*
