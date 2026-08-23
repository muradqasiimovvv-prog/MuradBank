# PT-01: Insecure Direct Object Reference (IDOR) — Unauthorized Account Access

## Severity
**High** (CVSS 3.1: 8.1 — AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

## CWE
CWE-639: Authorization Bypass Through User-Controlled Key

## OWASP Category
A01:2021 — Broken Access Control

## Affected Endpoint
- `GET /accounts/<account_id>`
- `GET /api/account-info/<account_id>`

## Affected Functionality
Account detail view (web page) and the underlying JSON API used to display balance, account number, and status for a single bank account.

## Description
Both endpoints retrieve an `Account` record directly by the `account_id` supplied in the URL path, but never verify that the account belongs to the currently authenticated user. Any logged-in user can enumerate sequential integer IDs and view **any other customer's account number, balance, and status**, including admin accounts.

Relevant code (`app/routes/accounts.py`):
```python
@accounts_bp.route('/<int:account_id>')
def view_account(account_id):
    check = check_login()          # only checks "is someone logged in?"
    if check:
        return check

    account = db.session.get(Account, account_id)   # no ownership check!
    ...
```

The same flaw exists in `app/routes/api.py`:
```python
@api_bp.route('/account-info/<account_id>', methods=['GET'])
def get_account_info(account_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    account = db.session.get(Account, account_id)   # no ownership check!
    ...
```

Both handlers authenticate the request (confirm *a* user is logged in) but fail to **authorize** it (confirm *this* user owns the requested resource) — a classic broken access control flaw.

## Attack Scenario
1. Attacker registers/logs into a low-privilege account (e.g. `alice`).
2. Attacker opens their own account page, e.g. `/accounts/1`, and notices the ID is a small sequential integer.
3. Attacker increments the ID (`/accounts/2`, `/accounts/3`, ...) and retrieves other customers' full account numbers and balances — including the bank's admin account.
4. Combined with the transfer feature (which trusts `from_account_id` from a `<select>` populated only in the UI, but the server only validates *ownership* of the source account — not that the attacker is barred from *viewing* other accounts first), the attacker can perform full account reconnaissance across the entire customer base before attempting further attacks (e.g. social engineering, targeted transfer fraud).

## Steps to Reproduce
1. Log in as `alice` / `password123`.
2. Note that Alice's own account is `id=1` (account number ending `...7890`).
3. Send a request for a different ID while authenticated as Alice:
   ```
   GET /accounts/2 HTTP/1.1
   Host: localhost:5000
   Cookie: session=<alice_session_cookie>
   ```
4. Observe the response renders Bob's account (`id=2`) in full.
5. Repeat for `id=3` (the `admin` account) — also succeeds.
6. Repeat against the JSON API: `GET /api/account-info/3`.

## Proof of Concept

**Request (as Alice, requesting Bob's account):**
```http
GET /accounts/2 HTTP/1.1
Host: localhost:5000
Cookie: session=eyJpc19hZG1pbiI6ZmFsc2UsInVzZXJfaWQiOjEsInVzZXJuYW1lIjoiYWxpY2UifQ...
```

**Response:** `HTTP/200 OK`
```html
<h2>1002234567890</h2>
...
<td><strong>Balance:</strong></td>
<td>3000.0 AZN</td>
```

**API PoC (as Alice, requesting Admin's account):**
```bash
curl -b alice_cookies.txt http://localhost:5000/api/account-info/3
```
```json
{
  "account_number": "1003234567890",
  "balance": 10000.0,
  "id": 3,
  "owner_id": 3,
  "status": "active"
}
```
Alice (`user_id=1`) successfully retrieved the admin's (`user_id=3`) account balance and full account number without any authorization check.

## Impact
- **Confidentiality breach**: any authenticated user can view every other customer's account number and balance by simply incrementing an integer in the URL — full horizontal privilege escalation across the customer base.
- **Fraud enablement**: exposed account numbers can be used for social-engineering or SIM-swap-style fraud against real customers once real names are correlated (via `/profile` or the admin panel, itself also vulnerable — see PT-03).
- **Regulatory exposure**: for a real bank this is a reportable data breach (PCI-DSS / local banking-secrecy regulation violation).

## Root Cause
The application authenticates (`check_login()` / `'user_id' in session`) but never authorizes at the object level. The developer implicitly trusted that because a user is logged in, any resource ID they request is safe to return — no ownership/ACL check ties `Account.user_id` back to `session['user_id']`.

## Remediation
Add an explicit ownership check after loading the resource, before returning any data:

```python
@accounts_bp.route('/<int:account_id>')
def view_account(account_id):
    check = check_login()
    if check:
        return check

    account = db.session.get(Account, account_id)

    if not account or account.user_id != session['user_id']:
        return "Account not found", 404   # 404, not 403 — avoid leaking existence

    transactions = db.session.scalars(select(Transaction).filter(
        or_(Transaction.from_account_id == account_id,
            Transaction.to_account_id == account_id)
    )).all()

    return render_template('account_detail.html', account=account, transactions=transactions)
```

Apply the identical check to `app/routes/api.py::get_account_info`.

## Security Recommendation
1. **Centralize authorization**: create a reusable helper/decorator, e.g. `@require_account_ownership`, so every current and future endpoint touching an `Account` enforces the same rule — prevents the same bug from being reintroduced elsewhere.
2. **Prefer non-enumerable identifiers** for anything exposed in a URL (UUIDs) as defense-in-depth, though ownership checks remain mandatory regardless.
3. **Return 404, not 403**, for objects that exist but aren't owned by the requester, to avoid confirming the existence of arbitrary IDs to an attacker.
4. **Add automated regression tests** asserting that User A's session cannot read User B's account via any route.

## Evidence / Screenshots
- `docs/reports/evidence/PT-01-idor-bob-account.png` — Alice's browser session displaying Bob's account after navigating to `/accounts/2`.
- `docs/reports/evidence/PT-01-idor-api-admin.png` — curl output showing admin's balance retrieved via `/api/account-info/3` while authenticated as Alice.

---
**Status:** ✅ Confirmed & Reproduced | **Fixed in commit:** see `security: fix IDOR in accounts and api routes`
