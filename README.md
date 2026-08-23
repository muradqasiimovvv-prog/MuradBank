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

| # | Vulnerability | Severity | CWE | OWASP | Endpoint |
|---|---|---|---|---|---|
| 1 | Broken Access Control (IDOR) | High | CWE-639 | A01 | `/accounts/<account_id>` |
| 2 | SQL Injection | High | CWE-89 | A03 | `/api/search-transactions` |
| 3 | Broken Authentication | High | CWE-287 | A07 | `/admin`, Session Management |
| 4 | Stored XSS | High | CWE-79 | A03 | `/messages` |
| 5 | CSRF (Cross-Site Request Forgery) | Medium | CWE-352 | A01 | `/transfer/send` |
| 6 | Unsafe File Upload | High | CWE-434 | A04 | `/profile/edit` |
| 7 | SSRF (Server-Side Request Forgery) | Medium | CWE-918 | A10 | `/admin/check-url` |
| 8 | Business Logic Flaw | Medium | CWE-840 | A04 | `/transfer/send` |

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
│   │   ├── accounts.py      (IDOR vulnerability)
│   │   ├── transfer.py      (CSRF vulnerability)
│   │   ├── messages.py      (Stored XSS)
│   │   ├── profile.py       (File upload)
│   │   ├── admin.py         (Broken auth & SSRF)
│   │   └── api.py           (SQL injection)
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

## 🔐 Known Vulnerabilities (Intentional)

### IDOR (Insecure Direct Object Reference)
- **Location**: `/accounts/<account_id>`
- **Impact**: Access other users' account details
- **How to test**: Change account_id to access other accounts

### SQL Injection
- **Location**: `/api/search-transactions`
- **Impact**: Database data extraction
- **How to test**: Inject SQL in search parameter

### Stored XSS
- **Location**: `/messages` (support messages)
- **Impact**: Execute JavaScript in admin panel
- **How to test**: Send message with `<script>alert('XSS')</script>`

### Broken Authentication
- **Location**: `/admin`
- **Impact**: Admin privileges can be added via session manipulation
- **How to test**: Modify session `is_admin` value

### CSRF
- **Location**: `/transfer/send`
- **Impact**: Unauthorized money transfer
- **How to test**: No CSRF token validation

### Unsafe File Upload
- **Location**: `/profile/edit` (avatar upload)
- **Impact**: Upload malicious files
- **How to test**: Upload .php, .exe, or malicious scripts

### SSRF
- **Location**: `/admin/check-url`
- **Impact**: Access internal services
- **How to test**: Input `http://localhost:5000/admin` or `http://169.254.169.254`

### Business Logic Flaw
- **Location**: `/transfer/send`
- **Impact**: Manipulate transaction amounts
- **How to test**: Send negative amounts or bypass validation

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
