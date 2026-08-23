import math

from flask import Blueprint, render_template, request, session, redirect, url_for, flash, jsonify
from app.database import db
from app.models import Account, Transaction
from sqlalchemy import select

transfer_bp = Blueprint('transfer', __name__, url_prefix='/transfer')

def check_login():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))
    return None

@transfer_bp.route('/')
def index():
    check = check_login()
    if check:
        return check

    accounts = db.session.scalars(select(Account).filter_by(user_id=session['user_id'])).all()
    return render_template('transfer.html', accounts=accounts)

@transfer_bp.route('/send', methods=['POST'])
def send():
    check = check_login()
    if check:
        return check

    # FIXED (PT-05): CSRFProtect (see app/__init__.py) rejects any POST missing
    # a valid csrf_token before this view even runs.
    from_account_id = request.form.get('from_account_id')
    to_account_number = request.form.get('to_account_number')
    amount = request.form.get('amount')
    description = request.form.get('description')

    try:
        amount = float(amount)
    except ValueError:
        flash('Invalid amount', 'danger')
        return redirect(url_for('transfer.index'))

    # Get from account
    from_account = db.session.get(Account, from_account_id)
    if not from_account or from_account.user_id != session['user_id']:
        flash('Unauthorized', 'danger')
        return redirect(url_for('transfer.index'))

    # Get to account
    to_account = db.session.scalar(select(Account).filter_by(account_number=to_account_number))
    if not to_account:
        flash('Recipient account not found', 'danger')
        return redirect(url_for('transfer.index'))

    # FIXED (PT-08): reject NaN/inf as well as non-positive amounts, and cap
    # the maximum transfer size as a sane business rule.
    if not math.isfinite(amount) or amount <= 0:
        flash('Amount must be a positive, finite number', 'danger')
        return redirect(url_for('transfer.index'))

    if amount > 1_000_000:
        flash('Amount exceeds maximum allowed transfer', 'danger')
        return redirect(url_for('transfer.index'))

    if from_account.balance < amount:
        flash('Insufficient balance', 'danger')
        return redirect(url_for('transfer.index'))

    # Process transfer
    from_account.balance -= amount
    to_account.balance += amount

    transaction = Transaction(
        from_account_id=from_account.id,
        to_account_id=to_account.id,
        user_id=session['user_id'],
        amount=amount,
        description=description
    )

    db.session.add(transaction)
    db.session.commit()

    flash(f'Transfer successful! {amount} AZN sent.', 'success')
    return redirect(url_for('dashboard.index'))

@transfer_bp.route('/api/accounts', methods=['GET'])
def get_accounts():
    check = check_login()
    if check:
        return jsonify([])

    accounts = db.session.scalars(select(Account).filter_by(user_id=session['user_id'])).all()
    return jsonify([{
        'id': acc.id,
        'account_number': acc.account_number,
        'balance': acc.balance
    } for acc in accounts])
