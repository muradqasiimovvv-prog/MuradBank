# MuradBank — Security Findings Summary

Tracks every intentionally-planted vulnerability from discovery through remediation. This file is the single source of truth for engagement status — update the status column as each finding is closed.

## Findings Register

| ID | Vulnerability | Severity | CWE | Status | Found & Fixed By | Report |
|----|---------------|----------|-----|--------|-------------------|--------|
| PT-01 | IDOR — Unauthorized Account Access | High | CWE-639 | ✅ Fixed | Mentor demo | [PT-01](reports/PT-01-IDOR-Account-Access.md) |
| PT-02 | SQL Injection — Transaction Search | Critical | CWE-89 | ✅ Fixed | Mentor demo | [PT-02](reports/PT-02-SQL-Injection-Transaction-Search.md) |
| PT-03 | Stored XSS — Support Messages | High | CWE-79 | 🟡 Found — fix pending | **Murad** (found independently) | [PT-03](reports/PT-03-Stored-XSS-Support-Messages.md) |
| PT-04 | Broken Authentication — Admin Session Trust | High | CWE-287 | 🔲 Pending | *your turn* | — |
| PT-05 | CSRF — Money Transfer | Medium | CWE-352 | 🔲 Pending | *your turn* | — |
| PT-06 | Unrestricted File Upload — Avatar | High | CWE-434 | 🔲 Pending | *your turn* | — |
| PT-07 | SSRF — Admin URL Check | Medium | CWE-918 | 🔲 Pending | *your turn* | — |
| PT-08 | Business Logic Flaw — Transfer Validation | Medium | CWE-840 | 🔲 Pending | *your turn* | — |

**Progress: 2 / 8 closed, 1 / 8 found (fix pending)**

---

## Before / After — Fixed Findings

### PT-01: IDOR (`app/routes/accounts.py`, `app/routes/api.py`)

**Before (vulnerable):**
```python
account = db.session.get(Account, account_id)
if not account:
    return "Account not found", 404
```

**After (fixed):**
```python
account = db.session.get(Account, account_id)
if not account or account.user_id != session['user_id']:
    return "Account not found", 404
```

**What changed:** added an explicit ownership check comparing the resource's owning `user_id` against the authenticated session, and return a uniform 404 for both "doesn't exist" and "not yours" so an attacker can't distinguish the two cases.

**Verification:** cross-account requests (Alice → Bob's account, Alice → Admin's account) now return `404` instead of `200` with the target's data. Own-account access confirmed unaffected.

---

### PT-02: SQL Injection (`app/routes/api.py`)

**Before (vulnerable):**
```python
query = f"""
    SELECT * FROM transactions
    WHERE user_id = {session['user_id']}
    AND description LIKE '%{search_term}%'
"""
result = db.session.execute(text(query))
```

**After (fixed):**
```python
transactions = db.session.scalars(
    select(Transaction)
    .filter(Transaction.user_id == session['user_id'])
    .filter(Transaction.description.ilike(f'%{search_term}%'))
).all()
```

**What changed:** replaced raw string-concatenated SQL with the SQLAlchemy ORM query builder, which parameterizes every value automatically — user input can no longer break out of its intended data context, no matter what characters it contains.

**Verification:** baseline search still returns correct results; a UNION-based payload that previously dumped every user's password hash now returns an empty result set (treated as literal search text).

---

## Methodology Applied

Every finding in this register follows the same lifecycle:

```
RECON → ATTACK SURFACE → HYPOTHESIS → TEST → VALIDATION → IMPACT → EVIDENCE → REPORT → FIX → RE-VERIFY
```

1. **Recon / Attack Surface** — identify the endpoint and what user-controlled input reaches it.
2. **Hypothesis** — form a specific, testable guess (e.g. "this ID isn't checked against session ownership").
3. **Test** — send a crafted request as a low-privilege user to confirm or refute the hypothesis.
4. **Validation** — reproduce reliably, rule out false positives.
5. **Impact** — determine real-world consequence (data exposure, fraud, account takeover, etc.).
6. **Evidence** — capture exact request/response proving the flaw.
7. **Report** — write up using the standard PT-xx template (Severity, CWE, OWASP, Description, PoC, Root Cause, Remediation).
8. **Fix** — patch the root cause, not just the symptom.
9. **Re-verify** — repeat the original PoC against the fixed code and confirm it now fails; confirm legitimate functionality is unaffected (no regression).

## For the Remaining 6 Findings (PT-03 – PT-08)

These are intentionally left for hands-on discovery. For each one:
1. Pick an endpoint from the app and form a hypothesis about what could go wrong.
2. Use Burp Suite / curl / browser DevTools to test it against the running app.
3. Once confirmed, write the report using the same template as PT-01/PT-02 (see `docs/reports/` for the format).
4. Propose a fix; a mentor review checks it before it's committed.
5. Update this table's Status column and re-run this app to verify the fix holds.
