# PT-04: Broken Authentication — Session Forgery via Hardcoded Secret Key

## Severity
**Critical** (CVSS 3.1: 9.8 — AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H)

## CWE
CWE-287: Improper Authentication (also CWE-798: Use of Hard-coded Credentials)

## OWASP Category
A07:2021 — Identification and Authentication Failures

## Affected Endpoint
- `/admin` and every route under `admin_bp` (privilege check)
- Root cause lives in `app/config.py` (`SECRET_KEY`) and `app/routes/admin.py` (`check_admin()`)

## Affected Functionality
Every privilege check in the application relies entirely on trusting the contents of the client-supplied session cookie, which is itself signed with a hardcoded, publicly-known secret key.

## Description
Flask sessions are stored client-side as a cookie: `base64(json_payload).base64(timestamp).signature`. The payload (containing `user_id`, `username`, `is_admin`) is **not encrypted, only signed** — its integrity depends entirely on the server's `SECRET_KEY` being secret.

```python
# app/config.py
class Config:
    SECRET_KEY = 'dev-secret-key-change-in-production'  # VULNERABLE: weak secret
```

This key is hardcoded, low-entropy, and — because this is a public GitHub repository — **visible to anyone who reads the source code**. Combined with the authorization check in the admin panel:

```python
# app/routes/admin.py
def check_admin():
    if 'user_id' not in session:
        return False
    # VULNERABLE: Checking session['is_admin'] which is user-controlled!
    return session.get('is_admin', False)
```

...an attacker who knows the `SECRET_KEY` can construct a **validly-signed** session cookie asserting `is_admin: True` for any `user_id`, without ever authenticating as an admin or knowing the admin's password. The server has no independent way to verify `is_admin` against the database at request time — it fully trusts whatever the (attacker-forged, but correctly-signed) cookie claims.

## Attack Scenario
1. Attacker registers a normal, unprivileged customer account (or uses any existing low-privilege login).
2. Attacker obtains the `SECRET_KEY` — trivially, since it's hardcoded in the public source repository (in a real-world scenario this could also be recovered by brute-forcing common/weak secrets with tools like `flask-unsign --unsign`, since many Flask apps ship with predictable dev keys).
3. Attacker uses the `flask-unsign` tool to forge a new session cookie with `is_admin: True` for their own `user_id`, signed correctly with the known key.
4. Attacker replaces their browser's `session` cookie with the forged value.
5. Attacker navigates to `/admin` — the server verifies the signature (valid, since it was signed with the real key), trusts the embedded `is_admin: True` claim, and grants full admin panel access: user management, all transactions, all support messages, and the SSRF-vulnerable URL-check utility (PT-07).

## Steps to Reproduce
1. Log in as a normal user (`alice` / `password123`).
2. Inspect the `session` cookie (DevTools → Application → Cookies) and decode its first segment:
   ```javascript
   atob("eyJpc19hZG1pbiI6ZmFsc2UsInVzZXJfaWQiOjEsInVzZXJuYW1lIjoiYWxpY2UifQ")
   // → {"is_admin":false,"user_id":1,"username":"alice"}
   ```
   Confirms the payload is plaintext-readable and contains the authorization-critical `is_admin` flag.
3. Read the application's secret key directly from source: `cat app/config.py` → `SECRET_KEY = 'dev-secret-key-change-in-production'`.
4. Forge a new, validly-signed cookie:
   ```bash
   flask-unsign --sign --cookie "{'is_admin': True, 'user_id': 1, 'username': 'alice'}" \
     --secret 'dev-secret-key-change-in-production'
   ```
5. Replace the `session` cookie value in the browser with the forged output.
6. Navigate to `http://localhost:5000/admin/` — full admin dashboard loads (Total Users, Total Accounts, Total Transactions, Support Messages, Manage Users, View Messages) despite never having authenticated with admin credentials.

## Proof of Concept

**Decoded original cookie payload (as `alice`, unprivileged):**
```json
{"is_admin": false, "user_id": 1, "username": "alice"}
```

**Forged cookie payload (attacker-crafted, self-signed with the known key):**
```json
{"is_admin": true, "user_id": 1, "username": "alice"}
```

**Result:** `GET /admin/` → `200 OK`, full admin dashboard rendered (see evidence screenshot — Total Users: 3, Total Accounts: 3, Total Transactions: 1, Support Messages: 4, with "Manage Users" and "View Messages" admin-only actions available).

## Impact
- **Complete authentication/authorization bypass**: any registered user — including a brand-new, self-registered attacker account — can become admin without credentials.
- **Full administrative control**: access to `Manage Users` (including the ability to promote/demote any account's admin flag via PT-08-adjacent broken authorization), `View Messages` (reads every customer's support content, compounding PT-03's stored XSS by giving the attacker a direct path to also *be* the admin victim), and the SSRF-vulnerable URL-check tool (PT-07).
- **No detection surface**: because the forged cookie is cryptographically valid (correctly signed), the server cannot distinguish it from a legitimate admin session — there is no anomaly to log or alert on with the current implementation.
- Rated **Critical** rather than High because the barrier to full administrative compromise is a single hardcoded string, requires no interaction from any other user, and grants the highest privilege level in the system.

## Root Cause
Two compounding issues:
1. **Hardcoded, low-entropy `SECRET_KEY`** committed to source control — the single most common real-world cause of Flask session-forgery vulnerabilities.
2. **Trusting client-supplied authorization claims** — `is_admin` is read directly from the session cookie rather than being re-verified against the `User` record in the database on each privileged request. Even with a strong, properly-managed secret key, baking authorization state into a long-lived client-side token is fragile: it can't be revoked without invalidating the whole session, and it duplicates a source of truth that already exists safely in the database.

## Remediation

**Fix 1 — use a strong, environment-provided secret key, never hardcoded:**
```python
import os

class Config:
    SECRET_KEY = os.environ['SECRET_KEY']  # fails fast if not set; generate with secrets.token_hex(32)
```

**Fix 2 (defense in depth, addresses the deeper issue) — re-verify privilege from the database instead of trusting the session claim:**
```python
# app/routes/admin.py
def check_admin():
    if 'user_id' not in session:
        return False
    user = db.session.get(User, session['user_id'])
    return user is not None and user.is_admin   # source of truth = DB, not client-supplied cookie
```
With this change, even a perfectly-forged cookie claiming `is_admin: True` is useless unless the corresponding database row is *actually* flagged as admin — collapsing the attack surface back down to "attacker needs to already be an admin in the DB," which is the correct trust boundary.

## Security Recommendation
1. **Never commit secrets to source control** — use environment variables or a secrets manager, and add a startup check that refuses to run with a known-weak/default key.
2. **Re-verify authorization server-side on every privileged action**, not just at login — session data should carry *identity* (who is this?), not *authorization* (what can they do?); authorization should be re-derived from the database (or a short-lived, revocable token) on each request.
3. **Rotate the secret key** immediately (this also invalidates all existing sessions, which is the correct incident response to a leaked key).
4. **Add server-side session storage** (e.g. Flask-Session with a Redis/DB backend) for anything privilege-sensitive, so sessions can be centrally revoked/invalidated, not just cryptographically validated.
5. **Add a regression test**: attempt to access `/admin/` with a manually-forged cookie asserting `is_admin: True` for a known non-admin user ID, using the *correct* key, and assert the response is `403`, not `200` — this specifically tests Fix 2, not just key strength.

## Evidence / Screenshots
- `docs/reports/evidence/PT-04-cookie-decode.png` — decoded session payload showing plaintext `is_admin: false` for Alice.
- `docs/reports/evidence/PT-04-admin-access.png` — full Admin Dashboard (`/admin/`) loaded after replacing the session cookie with a `flask-unsign`-forged token, while never having authenticated as `admin`.

---
**Status:** ✅ Confirmed & Reproduced (found independently, `flask-unsign` PoC executed successfully) | **Fix:** pending — assigned as self-remediation exercise
