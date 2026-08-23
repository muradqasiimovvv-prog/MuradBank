# PT-03: Stored Cross-Site Scripting (XSS) — Support Messages

## Severity
**High** (CVSS 3.1: 7.4 — AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N — capped by HttpOnly session cookie, see Impact)

## CWE
CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-Site Scripting)

## OWASP Category
A03:2021 — Injection

## Affected Endpoint
- `POST /messages/new` (injection point)
- `GET /messages/<message_id>` (execution point — where the payload fires)
- `GET /admin/messages` (secondary execution point — admin views all users' messages)

## Affected Functionality
The customer support "Message" feature, where a logged-in user submits a subject/content/category to the bank's support team, and later views that message (as can an admin, via the admin message-review panel).

## Description
The message `content` field is stored verbatim in the database and rendered back using Jinja2's `|safe` filter, which explicitly disables Jinja's default HTML auto-escaping:

```html
<!-- app/templates/view_message.html -->
<div class="message-content">
    {{ message.content|safe }}
</div>
```

The same unsafe pattern is repeated in the admin message list:

```html
<!-- app/templates/admin_messages.html -->
<div style="max-width: 300px; overflow: hidden;">
    {{ msg.content|safe }}
</div>
```

Notably, the **subject** field on the same page is rendered *without* `|safe` and is correctly escaped — this inconsistency (one field safe, one not) is what makes the flaw easy to miss in code review and demonstrates why every output context needs to be checked individually, not just "the page" as a whole.

Because `content` accepts arbitrary HTML/JS and is later displayed to other users (most importantly the bank's own admin, who reviews all support messages), this is a **Stored** XSS: the attacker does not need to trick a victim into clicking a crafted link — simply waiting for the victim (or admin) to open their inbox is enough.

## Attack Scenario
1. Attacker registers a normal customer account.
2. Attacker opens "New Message" and submits a support request where the `content` field contains a JavaScript payload instead of a real message.
3. Attacker waits. The message sits in the `messages` table exactly as submitted.
4. Any user who later views that specific message — most critically, **the bank admin reviewing support tickets** via `/admin/messages` — has the attacker's JavaScript executed in their browser, in the security context of `localhost:5000` (the bank's own origin), while authenticated as admin.
5. Even though the session cookie itself is `HttpOnly` (not directly readable via `document.cookie` — see Impact), the attacker's script still runs with full DOM access and can perform any action the admin's browser is authorized to do via `fetch()`/`XMLHttpRequest` (e.g. silently call `POST /admin/users/<id>/edit` to promote an arbitrary account to admin), effectively turning this into a **CSRF-free session-riding primitive inside the admin panel**.

## Steps to Reproduce
1. Log in as `alice` / `password123`.
2. Navigate to **Messages → New Message**.
3. Submit:
   - Subject: `XSS Test`
   - Content: `<b>test</b>`
4. Open the sent message from the list ("Bax"). Observe the subject renders literally (`<b>test</b>` as text) while the content renders **bold** — confirming `content` is output without escaping while `subject` is escaped correctly.
5. Submit a second message with content:
   ```html
   <script>alert('XSS: ' + document.cookie)</script>
   ```
6. Open the message again — a JavaScript `alert()` fires immediately on page load, confirming full script execution, not just HTML tag injection.

## Proof of Concept

**Payload 1 — confirm HTML injection (baseline):**
```html
Subject: XSS Test
Content: <b>test</b>
```
Result: subject displayed literally; content rendered **bold** — proves `content` bypasses HTML escaping (`|safe` in `view_message.html`).

**Payload 2 — confirm script execution:**
```html
Content: <script>alert('XSS: ' + document.cookie)</script>
```
Result: `alert()` dialog fires on page load reading **`XSS: `** (empty). See evidence screenshot — `localhost:5000 says: XSS:` with no cookie value appended.

**Raw HTML response (via curl, unescaped as delivered by the server):**
```html
<div class="message-content">
    <!-- VULNERABLE: XSS - content is not escaped -->
    <b>test</b>
</div>
```

## Impact
- **Confirmed arbitrary JavaScript execution** in the victim's browser, in the bank application's own origin — the foundational primitive for session riding, UI redressing/phishing overlays, keylogging on the page, and defacement.
- **Partially mitigated by `HttpOnly`**: the session cookie cannot be read via `document.cookie`, so *direct* cookie theft/session-token exfiltration is blocked. This is a real, working defense-in-depth control worth noting positively in the report — but it is **not sufficient** on its own.
- **Session-riding risk remains despite `HttpOnly`**: injected script executing inside an authenticated admin's browser can still issue `fetch()` requests to any endpoint using the admin's live session (cookies are sent automatically by the browser even though JS cannot read them), meaning an attacker could silently trigger privileged actions (e.g. self-promote to admin via the admin panel's broken-authorization endpoint — see PT-04) without ever needing the raw cookie value.
- **Trust-boundary violation**: a low-privileged customer can plant code that executes in the browser of the bank's own staff — the most damaging XSS pattern (attacker → admin), since it directly threatens the highest-privilege account in the system.

## Root Cause
`app/templates/view_message.html` and `app/templates/admin_messages.html` both use Jinja2's `|safe` filter on user-controlled `message.content`, explicitly opting out of Jinja's default context-aware auto-escaping. There is no server-side sanitization (e.g. an allow-list HTML sanitizer) applied to `content` at input time either — the raw value submitted by the user is stored as-is and later trusted at render time.

## Remediation
**Primary fix — stop bypassing auto-escaping.** Simply remove `|safe`; Jinja2 auto-escapes by default, which is sufficient if the feature only needs to display plain text:

```html
<!-- app/templates/view_message.html -->
<div class="message-content">
    {{ message.content }}
</div>
```
```html
<!-- app/templates/admin_messages.html -->
<div style="max-width: 300px; overflow: hidden;">
    {{ msg.content }}
</div>
```

If basic formatting (line breaks, bold, links) is a genuine product requirement, do **not** re-enable `|safe`. Instead sanitize on input or output with an allow-list HTML sanitizer (e.g. `bleach` in Python) that strips everything except a small set of safe tags/attributes:

```python
import bleach

ALLOWED_TAGS = ['b', 'i', 'br', 'p']
clean_content = bleach.clean(raw_content, tags=ALLOWED_TAGS, strip=True)
```

## Security Recommendation
1. **Treat `|safe` (and equivalents like `Markup()`, `mark_safe()`, `dangerouslySetInnerHTML` in other stacks) as a code-review red flag** — it should require an explicit justification comment and, ideally, a sanitization step immediately before it, every single time it's used.
2. **Add a Content-Security-Policy header** (e.g. `script-src 'self'`) as defense-in-depth — would not fix the injection but would block inline `<script>` payloads like the one used in this PoC from executing at all, significantly raising the bar for exploitation.
3. **Set `SESSION_COOKIE_HTTPONLY = True`** explicitly in Flask config (confirm it's not only a Werkzeug default) and additionally set `SESSION_COOKIE_SAMESITE = 'Lax'` or `'Strict'` to further reduce cross-context session-riding risk.
4. **Add a regression test** asserting that a message containing `<script>` or `<img onerror=...>` renders as literal escaped text in both `view_message.html` and `admin_messages.html`.
5. **Audit every other free-text field** in the app rendered back to any user (e.g. transaction `description`, beneficiary `name`) for the same `|safe` pattern.

## Evidence / Screenshots
- `docs/reports/evidence/PT-03-xss-bold-render.png` — subject shown literally vs. content rendered bold, proving inconsistent escaping between the two fields.
- `docs/reports/evidence/PT-03-xss-alert-popup.png` — `alert('XSS: ' + document.cookie)` firing on page load at `localhost:5000/messages/4`, with `document.cookie` returning empty due to `HttpOnly`.

---
**Status:** ✅ Confirmed & Reproduced (found independently during hands-on testing) | **Fix:** pending — assigned as self-remediation exercise
