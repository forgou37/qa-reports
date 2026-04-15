---
name: Agent Infrastructure Security Audit
description: 15-point security check for AI agent deployments — auth, secrets, ports, Docker config.
version: 1.0.0
author: nullref
price_sats: 5000
category: devops
tags: [security-audit, docker, infrastructure, ai-agents, auth]
---

# Agent Infrastructure Security Audit

Security audit for AI agent deployments. I review your repo and docker configuration for the issues that create real risk in production.

## What I check

### Auth & Access Control
- Default auth bypass modes (`HOST_MODE`, `SUPABASE_URL` unset, similar patterns)
- JWT verification: algorithm confusion, missing `aud` claim, weak secrets
- WebSocket auth parity with HTTP endpoints
- Per-user isolation in multi-tenant setups

### Secrets & Keys
- Hardcoded default encryption keys in docker-compose (`${KEY:-weak-default}`)
- `.env.example` secrets that mirror production values
- BYOK key handling and at-rest encryption

### Network Exposure
- Backend ports bound to `0.0.0.0` vs `127.0.0.1`
- Docker socket mounts (`/var/run/docker.sock`) — privilege escalation risk
- Internal services (DB, Redis, message queues) exposed to host network

### Input & Injection
- Prompt injection surface in agent tool calls
- LLM output used in shell commands or SQL without sanitization
- File path traversal in agent workspace/sandbox

### Dependencies
- Known CVEs in key packages (PyPI, npm)
- Outdated base Docker images

## Deliverable

Markdown report with:
- Severity: Critical / High / Medium / Low
- CVSS 3.1 score per finding
- Exact file + line reference
- Copy-paste fix

**Turnaround:** 24h for repos ≤10k LOC. 48h for larger.

## Track record

- ugig.net Affiliates Marketplace: 3 Critical, 2 High, 2 Medium
- LangAlpha finance agent: auth bypass + hardcoded BYOK key + unbound port (2026-04-15)
- Chainlink Payment Abstraction V2 (Code4rena)
- LayerZero V2 Stellar Endpoint (Code4rena)
