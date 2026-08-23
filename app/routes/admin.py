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
    """VULNERABLE: Simple check that can be bypassed"""
    if 'user_id' not in session:
        return False
    # VULNERABLE: Checking session['is_admin'] which is user-controlled!
    return session.get('is_admin', False)

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
    """VULNERABLE: SSRF endpoint"""
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
