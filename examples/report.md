# LaunchGuard RN Report

**Project:** Example React Native app
**Launch Readiness Score:** 72/100

## Finding Example

### Supabase detected but RLS/policy evidence not found
**Severity:** high

**Why it matters:** Supabase projects need Row Level Security and policies to prevent cross-user data leaks.

**Fix:** Enable RLS on every user-data table and create least-privilege policies.

**Codex / Claude / Cursor Prompt:**
```
Audit Supabase usage. Add a checklist and SQL examples for enabling RLS, owner-scoped policies, safe anon key usage, and public bucket review.
```
