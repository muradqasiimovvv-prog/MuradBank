# PT-06: Unrestricted File Upload — Avatar Upload Leading to Stored XSS

## Severity
**High** (CVSS 3.1: 8.7 — AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:N)

## CWE
CWE-434: Unrestricted Upload of File with Dangerous Type

## OWASP Category
A04:2021 — Insecure Design

## Affected Endpoint
- `POST /profile/edit` (upload point)
- `GET /static/uploads/<filename>` (execution point — Flask's default static file serving)

## Affected Functionality
The profile avatar upload feature, intended to accept image files (JPG/PNG/GIF).

## Description
The upload handler validates neither the file's extension nor its actual content type before saving it into the application's `static/uploads/` directory:

```python
# app/routes/profile.py
if 'avatar' in request.files:
    file = request.files['avatar']

    if file and file.filename != '':
        # VULNERABLE: No file type validation!
        filename = secure_filename(file.filename)
        upload_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)

        os.makedirs(current_app.config['UPLOAD_FOLDER'], exist_ok=True)
        file.save(upload_path)
        user.avatar = filename
```

`ALLOWED_EXTENSIONS` is defined in `app/config.py` but is **never actually checked** anywhere in the upload code path — it exists only as unused configuration, giving a false sense of security to anyone skimming the config file. `secure_filename()` does sanitize the *filename itself* (preventing path traversal), but it does nothing to restrict the file's *extension* or *content*.

Because the upload target directory (`app/static/uploads/`) lives inside Flask's `static` folder, every file saved there is automatically served back by Flask's built-in static file route at `/static/uploads/<filename>` — with no authentication, no access control, and critically, **served with a `Content-Type` that lets the browser interpret `.html` files as HTML**, not as inert downloads.

## Attack Scenario
1. Attacker registers a normal account and goes to Edit Profile → Avatar upload.
2. Instead of an image, the attacker uploads a file named `evil.html` containing an embedded `<script>` payload.
3. The server accepts the file with no validation and saves it to a **predictable, public path**: `/static/uploads/evil.html`.
4. Attacker shares this direct link (e.g. `http://<bank-domain>/static/uploads/evil.html`) via phishing email, a support message (compounding PT-03), or any other delivery vector.
5. Any victim who opens that link gets the attacker's JavaScript executed **in the bank's own origin** — with the exact same consequences as the stored XSS in PT-03 (session-riding via `fetch()`, phishing overlays, etc.), but reachable by any registered user, not only via the support-message flow, and without needing an admin to specifically open a ticket.

## Steps to Reproduce
1. Log in as `alice` / `password123`.
2. Create a text file with an XSS payload instead of an image:
   ```bash
   echo '<script>alert("File Upload XSS: " + document.location)</script>' > /tmp/evil.html
   ```
3. Go to **Profile → Edit Profile**, select `evil.html` in the Avatar file picker, and save.
4. Server responds success; no error about invalid file type.
5. Navigate directly to `http://localhost:5000/static/uploads/evil.html`.
6. Observe the `alert()` fires immediately, confirming the browser rendered and executed the uploaded file as live HTML/JavaScript on the bank's own origin.

## Proof of Concept

**Uploaded file (`evil.html`):**
```html
<script>alert("File Upload XSS: " + document.location)</script>
```

**Result:** navigating to `http://localhost:5000/static/uploads/evil.html` triggers:
```
localhost:5000 says
File Upload XSS: http://localhost:5000/static/uploads/evil.html
```
confirming the file was accepted with no type/content restriction and is served as executable HTML from the application's own trusted origin.

## Impact
- **Stored XSS on the application's own origin**, reachable by any registered user (no admin interaction required, unlike PT-03) — broadens the attack surface for session-riding, credential-harvesting overlays, and defacement to *every* user, not just admins reviewing messages.
- **No file size/type ceiling observed beyond Flask's global `MAX_CONTENT_LENGTH`** — an attacker could also upload arbitrarily large files (storage exhaustion / DoS) or files with misleading extensions for social-engineering purposes (e.g. `invoice.pdf.html` if extension checks were naively added later without checking MIME type too).
- Depending on future deployment environment, an unrestricted upload endpoint is also the classic first step toward remote code execution if the server is ever reconfigured to execute uploaded files (e.g. `.php` on a misconfigured PHP-enabled host) — not applicable to this Flask/WSGI deployment today, but a pattern worth flagging as inherently dangerous regardless of current runtime.
- Rated **High** rather than Critical because, in this specific deployment, impact is capped at script execution (same ceiling as PT-03), not direct code execution on the server.

## Root Cause
- No server-side validation of file extension or actual content/MIME type at upload time — the `ALLOWED_EXTENSIONS` config value is defined but dead code, never referenced by the upload handler.
- Uploaded files are stored inside the `static/` directory, which Flask serves automatically and generically — any file type placed there is servable, including types the browser will actively execute (HTML, SVG with embedded scripts, etc.).

## Remediation
**Fix 1 — actually enforce the existing `ALLOWED_EXTENSIONS` allow-list:**
```python
def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in current_app.config['ALLOWED_EXTENSIONS']

if file and file.filename != '':
    if not allowed_file(file.filename):
        flash('Invalid file type. Only images are allowed.', 'danger')
        return redirect(url_for('profile.edit'))
    filename = secure_filename(file.filename)
    ...
```

**Fix 2 (defense in depth) — validate actual content, not just the extension**, since an attacker can rename `evil.html` to `evil.jpg` and the extension check alone won't catch it:
```python
from PIL import Image

file.stream.seek(0)
try:
    Image.open(file.stream).verify()   # raises if not a genuine image
except Exception:
    flash('File is not a valid image.', 'danger')
    return redirect(url_for('profile.edit'))
file.stream.seek(0)
```

**Fix 3 (defense in depth) — serve uploads from outside the auto-executing static path**, or force safe delivery even if a bad file slips through:
```python
# Serve uploads through a dedicated route that forces download / safe content-type
from flask import send_from_directory

@profile_bp.route('/uploads/<filename>')
def serve_upload(filename):
    return send_from_directory(
        current_app.config['UPLOAD_FOLDER'], filename,
        mimetype='application/octet-stream',   # never let the browser execute it
        as_attachment=True
    )
```

## Security Recommendation
1. **Validate both extension AND actual file content** (magic-byte/library-based check) — extension checks alone are trivially bypassed by renaming a file.
2. **Never serve user-uploaded content from the same origin as the application** if avoidable — use a separate subdomain or object storage bucket with no script-execution capability, so even a successful malicious upload can't run in the bank's trusted origin.
3. **Set a strict `Content-Security-Policy`** as defense in depth (as also recommended in PT-03) — would prevent inline `<script>` execution even from an uploaded HTML file.
4. **Re-encode uploaded images** (e.g. re-save through Pillow) rather than storing the original bytes — strips any embedded payload riding inside a technically-valid image file (e.g. polyglot GIF/JS files).
5. **Add a regression test** uploading a `.html`, `.svg` with embedded `<script>`, and a renamed `evil.jpg` (actually HTML) — assert all three are rejected or safely neutralized.

## Evidence / Screenshots
- `docs/reports/evidence/PT-06-upload-success.png` — `evil.html` accepted by the avatar upload form with no error.
- `docs/reports/evidence/PT-06-xss-alert.png` — `alert()` firing when navigating directly to `http://localhost:5000/static/uploads/evil.html`.

---
**Status:** ✅ Confirmed & Reproduced (found and exploited independently) | **Fix:** deferred — all findings will be remediated together in a final fix pass (see [FINDINGS-SUMMARY.md](../FINDINGS-SUMMARY.md))
