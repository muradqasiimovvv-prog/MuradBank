# PT-07: Server-Side Request Forgery (SSRF) — Admin URL Check Utility

## Severity
**Medium** (CVSS 3.1: 6.5 — AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N — capped by requiring existing admin privilege, see Impact)

## CWE
CWE-918: Server-Side Request Forgery (SSRF)

## OWASP Category
A10:2021 — Server-Side Request Forgery

## Affected Endpoint
`POST /admin/check-url`

## Affected Functionality
An admin-only utility (API-only — no linked UI element exists in the current admin dashboard) that fetches an arbitrary attacker/admin-supplied URL server-side and returns its status code and response body.

## Description
The endpoint takes a `url` parameter directly from the request and passes it, unvalidated, to the `requests` library, which executes server-side:

```python
# app/routes/admin.py
@admin_bp.route('/check-url', methods=['POST'])
def check_url():
    check = check_login()
    if check:
        return check

    if not check_admin():
        return jsonify({'error': 'Unauthorized'}), 403

    url = request.form.get('url')

    # VULNERABLE: No URL validation, can access internal services
    try:
        import requests
        response = requests.get(url, timeout=5)
        return jsonify({
            'status_code': response.status_code,
            'content': response.text[:500]
        })
    except Exception as e:
        return jsonify({'error': str(e)})
```

There is no allow-list of permitted hosts/schemes, no block-list of private/link-local address ranges (`127.0.0.0/8`, `169.254.0.0/16`, `10.0.0.0/8`, etc.), and no restriction on which ports can be targeted. The server will attempt a connection to **any** URL supplied, and reflects the response (status code + up to 500 bytes of body) straight back to whoever called the endpoint — turning the bank's own server into an open network proxy for its admin.

## Attack Scenario
1. An attacker who has obtained admin-level access (e.g. via PT-04's session-forgery flaw, or a legitimately compromised admin credential) uses this endpoint as a pivot point into the internal network the bank server sits on.
2. In a cloud deployment (AWS/Azure/GCP), the attacker targets the instance metadata service (`http://169.254.169.254/latest/meta-data/...` on AWS), which is normally only reachable *from the server itself* — never from the public internet. A successful request can leak the server's **IAM role credentials**, environment secrets, or internal hostnames.
3. Even without cloud metadata being present, the attacker can use the endpoint to port-scan and fingerprint internal-only services (databases, admin tools, other microservices) that are not exposed to the internet, using response time/content/error differences to map the internal network — reconnaissance that would otherwise require an actual foothold inside the network perimeter.
4. Any internal service reachable without its own separate authentication (e.g. an internal admin tool that trusts network position, a Redis/Memcached instance, an internal API) becomes directly readable/callable through this endpoint.

## Steps to Reproduce
1. Log in as `admin` / `admin123` (or forge an admin session per PT-04).
2. Send a baseline request (no UI form exists — crafted directly in Burp Repeater):
   ```
   POST /admin/check-url HTTP/1.1
   Host: localhost:5000
   Cookie: session=<admin_session_cookie>
   Content-Type: application/x-www-form-urlencoded

   url=https://example.com
   ```
   Confirms `200 OK` with `example.com`'s HTML reflected back — the endpoint works as an unrestricted URL fetcher.
3. Probe the cloud-metadata address:
   ```
   url=http://169.254.169.254/latest/meta-data/
   ```
4. Probe an internal-only target (the app's own loopback address):
   ```
   url=http://127.0.0.1:5000/admin/
   ```

## Proof of Concept

**Baseline (external URL, confirms the fetcher works at all):**
```json
{ "status_code": 200, "content": "<!doctype html>...<title>Example Domain</title>..." }
```

**Cloud-metadata probe (link-local address — classic SSRF target):**
```json
{
  "error": "HTTPConnectionPool(host='169.254.169.254', port=80): Max retries exceeded with url: /latest/meta-data/ (Caused by NewConnectionError(\"...Connection refused\"))"
}
```
No allow-list rejected this request outright — the server *attempted* the TCP connection to the link-local metadata address, and only failed because no such service exists in this local lab environment. In a real cloud deployment, this exact request would return `200 OK` with sensitive instance credentials in the body.

**Internal loopback probe (proves no internal/external host distinction exists):**
```json
{
  "status_code": 200,
  "content": "<!DOCTYPE html>...<title>Giriş Et - MuradBank</title>..."
}
```
The server successfully reached `127.0.0.1:5000` — its own loopback interface — and reflected the response. This confirms the endpoint applies **zero restriction** on target host: external internet, internal loopback, and non-routable link-local addresses are all treated identically.

## Impact
- **Internal network reconnaissance and access** from an endpoint that should only ever need to reach the public internet (if it needs to exist at all).
- **Cloud credential theft risk**: in any cloud-hosted deployment, this is a direct path to instance metadata credentials — one of the most damaging SSRF outcomes in modern cloud architecture, potentially escalating to full cloud account compromise.
- **Bypasses network-perimeter controls**: any internal service that relies on "not being reachable from outside" as its security boundary is fully exposed via this endpoint, since requests originate from *inside* the trusted network (the bank server itself).
- Rated **Medium** rather than Critical/High because exploitation requires an existing admin session (`PR:H` in the CVSS vector) — though note this bar is trivially cleared via PT-04's session-forgery flaw, meaning **PT-04 + PT-07 chained together give an unauthenticated external attacker a path to internal network access with no legitimate credentials at all.**

## Root Cause
User-supplied input (`url`) is passed directly to an outbound HTTP client (`requests.get`) with no validation of scheme, host, or destination IP range. The developer's threat model apparently considered only "is the requester an admin?" and not "should even an admin's request be allowed to target arbitrary internal infrastructure?".

## Remediation

**Primary fix — validate and restrict the destination before making the request:**
```python
import ipaddress
import socket
from urllib.parse import urlparse

ALLOWED_SCHEMES = {'http', 'https'}
BLOCKED_NETWORKS = [
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('169.254.0.0/16'),   # link-local / cloud metadata
    ipaddress.ip_network('::1/128'),
]

def is_safe_url(url):
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        return False
    try:
        resolved_ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
    except (socket.gaierror, ValueError):
        return False
    return not any(resolved_ip in net for net in BLOCKED_NETWORKS)

@admin_bp.route('/check-url', methods=['POST'])
def check_url():
    ...
    url = request.form.get('url')
    if not is_safe_url(url):
        return jsonify({'error': 'URL not allowed'}), 400
    response = requests.get(url, timeout=5, allow_redirects=False)  # also disable redirects — see note
    ...
```

**Note on redirects:** even with the host check above, `allow_redirects=True` (the `requests` default) would let an attacker supply an *allowed* URL that then 302-redirects to a blocked internal address, bypassing the check entirely. Disable redirects, or re-validate the destination after every hop.

## Security Recommendation
1. **Prefer an allow-list of specific, known-good destinations** over a block-list of "bad" IP ranges where the feature's purpose permits it — block-lists are easy to bypass (DNS rebinding, IPv6, decimal/octal IP encoding, redirect chains).
2. **Resolve the hostname once and validate the resulting IP** (not just the hostname string) immediately before connecting, to prevent TOCTOU/DNS-rebinding attacks where the hostname resolves to a safe IP at validation time but a different (internal) IP at request time.
3. **Run outbound requests from a network-isolated egress proxy** with its own firewall rules, so even a bypass of the application-level check can't reach internal infrastructure.
4. **Remove or gate this utility entirely if it isn't a genuine product requirement** — the simplest fix for a feature with no real business need is deleting it.
5. **Add a regression test** asserting requests to `127.0.0.1`, `169.254.169.254`, and a `file://` scheme are all rejected before any outbound connection is attempted.

## Evidence / Screenshots
- `docs/reports/evidence/PT-07-ssrf-baseline.png` — Burp Repeater response for the `example.com` baseline request.
- `docs/reports/evidence/PT-07-ssrf-metadata-probe.png` — connection-refused error confirming the server attempted a connection to the AWS metadata address.
- `docs/reports/evidence/PT-07-ssrf-internal-loopback.png` — `200 OK` response reflecting the bank's own login page HTML, fetched via the server's loopback interface.

---
**Status:** ✅ Confirmed & Reproduced (found and exploited independently via Burp Repeater) | **Fix:** deferred — all findings will be remediated together in a final fix pass (see [FINDINGS-SUMMARY.md](../FINDINGS-SUMMARY.md))
