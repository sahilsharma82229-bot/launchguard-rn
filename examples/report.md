# LaunchGuard RN Report

**Launch Readiness Score:** 72/100

## Finding Example

### Possible hardcoded secret/API key
**Severity:** critical

**Why it matters:** Hardcoded secrets can be copied from public repos or app bundles.

**Fix:** Move secrets to backend, CI secrets, Firebase Remote Config, or secure environment handling.

**Codex Prompt:**
```
Scan this repo for hardcoded secrets/API keys. Move them to safe configuration, add .env examples, and ensure no real secret is committed.
```
