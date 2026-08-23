# PT-08: Business Logic Flaw — Improper Transfer Amount Validation Leading to Crash & Debug Information Disclosure

## Severity
**Medium** (CVSS 3.1: 5.3 — AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:L — see note on compounding severity in Impact)

## CWE
CWE-20: Improper Input Validation (primary) chained into CWE-248: Uncaught Exception and CWE-215: Information Exposure Through Debug Information

## OWASP Category
A04:2021 — Insecure Design (business logic) / A05:2021 — Security Misconfiguration (debug mode exposure)

## Affected Endpoint
`POST /transfer/send`

## Affected Functionality
Transfer amount validation, and the application's error-handling configuration.

## Description
The transfer amount is parsed using Python's built-in `float()` with only a positivity check afterward:

```python
# app/routes/transfer.py
try:
    amount = float(amount)
except ValueError:
    flash('Invalid amount', 'danger')
    return redirect(url_for('transfer.index'))
...
if amount <= 0:
    flash('Amount must be positive', 'danger')
    return redirect(url_for('transfer.index'))

if from_account.balance < amount:
    flash('Insufficient balance', 'danger')
    return redirect(url_for('transfer.index'))
```

This correctly rejects negative numbers and non-numeric strings — **but Python's `float()` also happily parses the special IEEE-754 values `"nan"` and `"inf"`/`"infinity"` (case-insensitively)**, neither of which is caught by `<= 0`:
- `float('nan') <= 0` evaluates to `False` (NaN compares unequal/false to everything) — passes the positivity check.
- `from_account.balance < float('nan')` also evaluates to `False` — passes the balance check too.

The request then proceeds to `db.session.commit()`, attempting to `INSERT` a `NaN` amount into the `transactions` table. Python's `sqlite3` driver silently binds `NaN` as SQL `NULL` when passed as a query parameter, which collides with the `amount` column's `NOT NULL` constraint, raising an unhandled `sqlalchemy.exc.IntegrityError`. Because the application runs with `debug=True` (`run.py`), Flask serves the full **Werkzeug interactive debugger** page in response — exposing the complete stack trace, the exact SQL statement, all bound parameter values (including the victim account IDs), and critically, **the debugger's session secret**, which is part of what protects the interactive `/console` endpoint if it were reachable.

## Attack Scenario
1. Attacker (any authenticated user, no special privilege needed) submits a transfer with `amount=nan`.
2. The request passes all business-logic validation checks (positivity, sufficient balance) despite `NaN` being a nonsensical monetary value.
3. The database rejects the malformed insert at the constraint level, which is the *only* reason this doesn't silently corrupt a balance — a fragile safety net the developer did not intentionally design (SQLAlchemy's automatic transaction rollback on the `IntegrityError` happens to also revert the in-memory balance changes that were staged in the same commit).
4. The resulting `500` response, served in debug mode, hands the attacker the exact SQL query structure, table/column names, other users' account IDs referenced in the failed query, and internal application file paths — reconnaissance information that materially assists further attacks (e.g. crafting more precise SQL injection payloads elsewhere, understanding the schema for IDOR account ID guessing).
5. Repeated requests of this kind constitute a lightweight denial-of-service vector against the transfer endpoint (each triggers a server-side exception and full traceback rendering) and, if this behavior generalizes to other numeric inputs application-wide, a broader input-validation gap.

## Steps to Reproduce
1. Log in as `alice` / `password123`.
2. Send (via Burp Repeater or the transfer form):
   ```
   POST /transfer/send
   from_account_id=1&to_account_number=1002234567890&amount=nan&description=test
   ```
3. Observe `HTTP/1.1 500 INTERNAL SERVER ERROR` with a full Werkzeug debug page in the response body.
4. Check Alice's balance afterward — confirmed unchanged (the `IntegrityError` rolled back the whole `commit()`, including the in-memory balance mutation), meaning this specific input does **not** achieve direct fund creation, but does achieve an application crash with sensitive information disclosure.

## Proof of Concept

**Payload:**
```
amount=nan
```

**Response (500, debug mode):**
```
sqlalchemy.exc.IntegrityError: (sqlite3.IntegrityError) NOT NULL constraint failed: transactions.amount
[SQL: INSERT INTO transactions (from_account_id, to_account_id, user_id, amount, description, status, transaction_type, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)]
[parameters: (1, 2, 1, nan, 'test', 'completed', 'transfer', '2026-08-23 16:40:42.612476')]
```
The traceback additionally exposed a Werkzeug debugger session value (`SECRET_ = "uqujoo0O1Gv7vv48dpfD"`) in the rendered debug page's inline script — part of the machinery that protects the interactive debug console (`/?__debugger__=yes&cmd=...`), which itself allows arbitrary Python code execution if reachable.

## Impact
- **Application crash / lightweight DoS** on the transfer endpoint via a single crafted request, no rate limiting observed elsewhere in the app either (compounds PT-04's login flow, which also had no brute-force protection).
- **Sensitive information disclosure**: full SQL statement, schema details, internal file paths, and other users' account identifiers exposed in every crash of this kind — significant reconnaissance value for an attacker chaining this with other findings (e.g. PT-01, PT-02).
- **Severity amplifier — debug mode itself**: `debug=True` in `run.py` is the root enabler of the information-disclosure half of this finding. In a real deployment where Werkzeug's debug console is reachable (not PIN-protected, or the PIN is derived from predictable machine information — a well-documented real-world Werkzeug weakness), this same crash path is a known vector toward full **remote code execution**, not merely information disclosure. This report treats it as Medium because in *this* lab configuration the debugger console itself isn't demonstrated as reachable, but this is flagged as the single highest-priority item to fix regardless of the specific input-validation bug that triggers it.
- No permanent data corruption was achieved in this specific case (SQLite's `NOT NULL` constraint and SQLAlchemy's transactional rollback accidentally provided protection) — but this should not be read as "safe by design"; it is safe by accident of an unrelated schema constraint.

## Root Cause
Two independent issues compounding each other:
1. **Insufficient numeric validation**: `float(amount)` accepts `nan`/`inf`/`-inf` as valid floats; the subsequent `<= 0` and balance comparisons do not account for non-finite values, since IEEE-754 NaN comparisons are always `False`.
2. **`debug=True` in a runnable entry point** (`run.py`) with no environment-based gate — any unhandled exception anywhere in the app surfaces the full interactive debugger to whoever triggered it, not just the developer running it locally.

## Remediation

**Fix 1 — reject non-finite amounts explicitly:**
```python
import math

try:
    amount = float(amount)
except ValueError:
    flash('Invalid amount', 'danger')
    return redirect(url_for('transfer.index'))

if not math.isfinite(amount) or amount <= 0:
    flash('Amount must be a positive, finite number', 'danger')
    return redirect(url_for('transfer.index'))

# Additional business-rule bound, e.g. a sane per-transfer maximum:
if amount > 1_000_000:
    flash('Amount exceeds maximum allowed transfer', 'danger')
    return redirect(url_for('transfer.index'))
```
Better still, use `Decimal` rather than `float` for all monetary values throughout the application — floating-point arithmetic is generally unsuitable for currency due to rounding/precision issues independent of this specific NaN bug.

**Fix 2 — never run with `debug=True` outside local development, and never let it be the default:**
```python
# run.py
import os

if __name__ == '__main__':
    app = create_app('development')
    debug_mode = os.environ.get('FLASK_DEBUG', '0') == '1'
    app.run(debug=debug_mode, host='localhost', port=5000)
```
For anything resembling a shared/deployed environment, add a custom Flask error handler that logs the full traceback server-side but returns a generic error page to the client — never the interactive debugger.

## Security Recommendation
1. **Centralize monetary input validation** into a single reusable function/type (e.g. a `PositiveDecimal` validator) used everywhere an amount is accepted, so this class of bug can't be reintroduced in a different endpoint later.
2. **Treat `debug=True` as a deploy-blocking configuration error** — add a startup assertion or CI check that fails the build if debug mode is enabled outside an explicit local-dev flag.
3. **Add generic 500-error handling** (`@app.errorhandler(500)`) that logs internally (e.g. to a file or monitoring service) but shows the user a safe, generic message — this protects against *any* future unhandled exception leaking internals, not just this specific one.
4. **Add a regression test suite for numeric edge cases** across every monetary input in the app: `nan`, `inf`, `-inf`, extremely large values, and extreme precision (`0.000000001`) — not just the negative/zero cases already covered.

## Evidence / Screenshots
- `docs/reports/evidence/PT-08-nan-crash-traceback.png` — full Werkzeug debug page showing the `IntegrityError`, SQL statement, and bound parameters after submitting `amount=nan`.
- `docs/reports/evidence/PT-08-balance-unchanged.png` — dashboard confirming Alice's balance was unaffected after the crash (transactional rollback, not intentional protection).

---
**Status:** ✅ Confirmed & Reproduced (found independently) | **Fix:** deferred — all findings will be remediated together in a final fix pass (see [FINDINGS-SUMMARY.md](../FINDINGS-SUMMARY.md))
