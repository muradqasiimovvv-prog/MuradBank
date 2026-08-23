import ipaddress
import socket
from urllib.parse import urlparse

from flask import Blueprint, render_template, request, session, redirect, url_for, flash, jsonify
from app.database import db
from app.models import User, Account, Transaction, Message
from sqlalchemy import select

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

def check_login():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))
    return None

def check_admin():
    """FIXED (PT-04): re-verify privilege from the database, never trust the
    client-supplied session claim alone — a forged/stale session cookie
    asserting is_admin=True is now worthless without a matching DB row."""
    if 'user_id' not in session:
        return False
    user = db.session.get(User, session['user_id'])
    return user is not None and user.is_admin

# FIXED (PT-07): block requests to internal/non-routable address ranges
_SSRF_BLOCKED_NETWORKS = [
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('169.254.0.0/16'),   # link-local / cloud metadata
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fc00::/7'),
]

def is_safe_url(url):
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname:
        return False
    try:
        resolved_ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
    except (socket.gaierror, ValueError):
        return False
    return not any(resolved_ip in net for net in _SSRF_BLOCKED_NETWORKS)

@admin_bp.route('/')
def dashboard():
    check = check_login()
    if check:
        return check

    # VULNERABLE: Only checks session variable (client-side session!)
    if not check_admin():
        return "Access Denied", 403

    users = db.session.scalars(select(User)).all()
    accounts = db.session.scalars(select(Account)).all()
    transactions = db.session.scalars(select(Transaction)).all()
    messages = db.session.scalars(select(Message)).all()

    return render_template('admin_dashboard.html',
                         users=users,
                         accounts=accounts,
                         transactions=transactions,
                         messages=messages)

@admin_bp.route('/users')
def users():
    check = check_login()
    if check:
        return check

    if not check_admin():
        return "Access Denied", 403

    users = db.session.scalars(select(User)).all()
    return render_template('admin_users.html', users=users)

@admin_bp.route('/users/<int:user_id>/edit', methods=['POST'])
def edit_user(user_id):
    check = check_login()
    if check:
        return check

    # VULNERABLE: Can promote any user to admin
    if not check_admin():
        return jsonify({'error': 'Unauthorized'}), 403

    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    is_admin = request.form.get('is_admin') == 'on'
    user.is_admin = is_admin
    db.session.commit()

    return jsonify({'success': True})

@admin_bp.route('/messages')
def view_messages():
    check = check_login()
    if check:
        return check

    if not check_admin():
        return "Access Denied", 403

    messages = db.session.scalars(select(Message)).all()
    return render_template('admin_messages.html', messages=messages)

@admin_bp.route('/check-url', methods=['POST'])
def check_url():
    check = check_login()
    if check:
        return check

    if not check_admin():
        return jsonify({'error': 'Unauthorized'}), 403

    url = request.form.get('url', '')

    # FIXED (PT-07): reject internal/link-local/loopback targets before connecting,
    # and disable redirects so an allowed URL can't 302 into a blocked one.
    if not is_safe_url(url):
        return jsonify({'error': 'URL not allowed'}), 400

    try:
        import requests
        response = requests.get(url, timeout=5, allow_redirects=False)
        return jsonify({
            'status_code': response.status_code,
            'content': response.text[:500]
        })
    except Exception:
        return jsonify({'error': 'Request failed'}), 502
