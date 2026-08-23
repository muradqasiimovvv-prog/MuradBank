# 🏦 MuradBank - Vulnerable Banking Web Application

A deliberately vulnerable banking web application for educational security testing and penetration testing practice.

## ⚠️ Disclaimer

**This application is intentionally vulnerable.** It is designed ONLY for:
- Educational purposes
- Authorized security testing
- Learning web application security
- Penetration testing practice in a controlled environment

**DO NOT use this application against any real systems without proper authorization.**

## 📋 Project Overview

MuradBank is a realistic banking web application with intentionally injected security vulnerabilities. It is designed to teach:

- Identification of web vulnerabilities
- Manual penetration testing techniques
- Secure coding practices
- Security vulnerability remediation
- Professional security reporting

## 🎯 Objectives

1. **Build** a realistic bank web application
2. **Create** attack surface with intentional vulnerabilities
3. **Pentest** the application and find vulnerabilities
4. **Report** findings in professional format
5. **Fix** vulnerabilities with secure coding
6. **Learn** AppSec and pentesting methodology

## 🏗️ Architecture

```
Frontend (HTML/CSS/JS) → Flask Backend → SQLite Database
                              ↓
                    Authentication & Authorization
                    Session Management
                    File Upload Handler
                    API Endpoints
```

## 🛠️ Technology Stack

- **Frontend**: HTML5, CSS3, Vanilla JavaScript
- **Backend**: Python 3.10+ with Flask 3.0
- **Database**: SQLite3
- **ORM**: SQLAlchemy
- **Security Testing**: Burp Suite, Browser DevTools

## 🚀 Quick Start

### Installation

```bash
# Clone repository
git clone <repo-url>
cd muradbank

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run application
python run.py
```

### Access Application

- **URL**: http://localhost:5000
- **Demo Users**:
  - Username: `alice` | Password: `password123`
  - Username: `bob` | Password: `password123`
  - Username: `admin` | Password: `admin123` (Admin account)

## 🔓 Intentional Vulnerabilities

Full findings register with status, before/after fixes, and methodology: **[docs/FINDINGS-SUMMARY.md](docs/FINDINGS-SUMMARY.md)**

| ID | Vulnerability | Severity | CWE | OWASP | Status |
|---|---|---|---|---|---|
| PT-01 | Broken Access Control (IDOR) | High | CWE-639 | A01 | ✅ Fixed — [report](docs/reports/PT-01-IDOR-Account-Access.md) |
| PT-02 | SQL Injection | Critical | CWE-89 | A03 | ✅ Fixed — [report](docs/reports/PT-02-SQL-Injection-Transaction-Search.md) |
| PT-03 | Stored XSS | High | CWE-79 | A03 | 🟡 Found — [report](docs/reports/PT-03-Stored-XSS-Support-Messages.md) |
| PT-04 | Broken Authentication | Critical | CWE-287 | A07 | 🟡 Found — [report](docs/reports/PT-04-Broken-Authentication-Session-Forgery.md) |
| PT-05 | CSRF (Cross-Site Request Forgery) | High | CWE-352 | A01 | 🟡 Found — [report](docs/reports/PT-05-CSRF-Money-Transfer.md) |
| PT-06 | Unsafe File Upload | High | CWE-434 | A04 | 🟡 Found — [report](docs/reports/PT-06-Unrestricted-File-Upload.md) |
| PT-07 | SSRF (Server-Side Request Forgery) | Medium | CWE-918 | A10 | 🔲 Open |
| PT-08 | Business Logic Flaw | Medium | CWE-840 | A04 | 🔲 Open |

> Endpoints and exploitation details for open findings are intentionally not published here — this is a hands-on pentest exercise. See `docs/reports/` for the two closed findings' full write-ups (including endpoint, PoC, and fix) once you're ready to compare notes.

## 📁 Project Structure

```
muradbank/
├── app/
│   ├── __init__.py          (Flask app factory)
│   ├── config.py            (Configuration)
│   ├── models.py            (Database models)
│   ├── database.py          (Database initialization)
│   ├── routes/              (Route handlers)
│   │   ├── auth.py          (Login/Register)
│   │   ├── dashboard.py     (Main page)
│   │   ├── accounts.py      (Account views — PT-01 fixed here)
│   │   ├── transfer.py      (Money transfer)
│   │   ├── messages.py      (Support messages)
│   │   ├── profile.py       (Profile & avatar upload)
│   │   ├── admin.py         (Admin panel)
│   │   └── api.py           (JSON API — PT-01 & PT-02 fixed here)
│   ├── templates/           (HTML templates)
│   └── static/
│       ├── css/style.css    (Styling)
│       ├── js/app.js        (JavaScript)
│       └── uploads/         (User uploads)
├── docs/                    (Documentation)
├── tests/                   (Tests)
├── requirements.txt
├── run.py                   (Entry point)
└── database.db             (SQLite database)
```

## 👥 Demo Accounts

| Username | Password | Role | Purpose |
|----------|----------|------|---------|
| alice | password123 | User | Testing user account |
| bob | password123 | User | Testing user account |
| admin | admin123 | Admin | Testing admin features |

## 📚 Features

### User Features
- ✅ User registration and login
- ✅ View multiple bank accounts
- ✅ Check account balance
- ✅ View transaction history
- ✅ Send money to other accounts
- ✅ Manage beneficiaries
- ✅ Support messages
- ✅ Profile management with avatar upload

### Admin Features
- ✅ Admin dashboard
- ✅ User management
- ✅ Transaction monitoring
- ✅ Support message review
- ✅ System logs
- ✅ URL check utility

## 🔐 Vulnerability Status

2 of 8 intentional vulnerabilities have been found, exploited, documented, and fixed as worked examples — see [docs/FINDINGS-SUMMARY.md](docs/FINDINGS-SUMMARY.md) for the full before/after and methodology. The remaining 6 are open, to be discovered through hands-on testing (Burp Suite, curl, browser DevTools) rather than read off this page.

## 🧪 Testing Methodology

### Phase 1: Reconnaissance
- [ ] Identify all endpoints
- [ ] Map application structure
- [ ] Analyze HTTP requests
- [ ] Identify input points

### Phase 2: Vulnerability Scanning
- [ ] Test for IDOR
- [ ] Test for injection (SQLi, XSS)
- [ ] Test for broken authentication
- [ ] Test for broken authorization
- [ ] Test for CSRF
- [ ] Test for file upload issues

### Phase 3: Exploitation
- [ ] Demonstrate vulnerability impact
- [ ] Create proof of concept
- [ ] Document attack chain
- [ ] Screenshot evidence

### Phase 4: Reporting
- [ ] Write technical findings
- [ ] Detail root causes
- [ ] Provide remediation advice
- [ ] Rate severity

## 📊 Expected Findings

- 8 confirmed vulnerabilities
- 3-5 high severity issues
- 2-3 medium severity issues
- Multiple attack chains
- Business impact analysis

## 🛡️ Security Review Checklist

- [ ] Input validation
- [ ] Output encoding
- [ ] Authentication mechanisms
- [ ] Authorization controls
- [ ] Session management
- [ ] CSRF protection
- [ ] File upload security
- [ ] API security
- [ ] Error handling
- [ ] Logging & monitoring

## 📝 Reporting Format

Each vulnerability should be documented as:

```
# Vulnerability Title

## Severity
Critical / High / Medium / Low

## CWE
CWE-XXX

## OWASP Category
A01/A02/.../A10

## Description
Detailed description of the vulnerability

## Affected Endpoint
/path/to/vulnerable/endpoint

## Steps to Reproduce
1. Step 1
2. Step 2
3. Step 3

## Proof of Concept
Code/screenshots demonstrating the vulnerability

## Impact
Business and technical impact

## Root Cause
Why the vulnerability exists

## Remediation
How to fix it

## Secure Implementation
Example of secure code
```

## 🚀 Running the Application

```bash
python run.py
```

Application will start on `http://localhost:5000`

## 📖 Learning Resources

- [OWASP Web Security Testing Guide (WSTG)](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP Top 10 2021](https://owasp.org/www-project-top-ten/)
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/)
- [Burp Suite Documentation](https://portswigger.net/burp)

## 🔧 Configuration

Edit `app/config.py` to modify:
- Database URI
- Upload folder size limits
- Allowed file types
- Secret key (change in production)

## 📧 Database

SQLite database is auto-created on first run with demo data:
- 3 demo users with accounts
- 1 demo transaction

## ⚡ Development Mode

Application runs in Flask debug mode:
- Auto-reload on code changes
- Interactive debugger
- Detailed error pages

**⚠️ Never run with `debug=True` in production!**

## 🎓 Educational Value

This project teaches:

1. **Vulnerability Identification**: How to recognize security flaws
2. **Exploitation Techniques**: Practical attack methods
3. **Secure Coding**: How to write secure code
4. **Security Testing**: Manual penetration testing
5. **Professional Reporting**: Security documentation
6. **Remediation**: Fixing vulnerabilities properly

## 📜 License

Educational use only. Not licensed for commercial use.

## ⚠️ Final Warning

**This application contains dangerous, intentional vulnerabilities. Use ONLY in:**
- Isolated lab environment
- Authorized testing scenarios
- Educational settings
- Your own machine

**Unauthorized access to computer systems is illegal.**

---

**Happy (legal) hacking! 🚀**
