#!/usr/bin/env python3
import os
from app import create_app

if __name__ == '__main__':
    app = create_app('development')
    # FIXED (PT-08): debug mode (and its interactive traceback/debugger) is now
    # opt-in only, never the default — set FLASK_DEBUG=1 for local development.
    debug_mode = os.environ.get('FLASK_DEBUG', '0') == '1'
    print("\n" + "="*60)
    print("🏦 MuradBank - Vulnerable Banking Application")
    print("="*60)
    print("⚠️  WARNING: This application intentionally contains security vulnerabilities")
    print("📝 Use for educational and authorized security testing only!")
    print("\n🌐 Starting server at http://localhost:5000")
    print("📚 Demo Credentials:")
    print("   - User: alice / password123")
    print("   - User: bob / password123")
    print("   - Admin: admin / admin123")
    print("="*60 + "\n")
    app.run(debug=debug_mode, host='localhost', port=5000)
