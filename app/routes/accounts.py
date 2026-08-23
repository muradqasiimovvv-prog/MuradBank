from flask import Blueprint, render_template, session, redirect, url_for
from app.database import db
from app.models import Account, Transaction
from sqlalchemy import select, or_

accounts_bp = Blueprint('accounts', __name__, url_prefix='/accounts')

def check_login():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))
    return None

@accounts_bp.route('/')
def index():
    check = check_login()
    if check:
        return check

    # Show only current user's accounts
    accounts = db.session.scalars(select(Account).filter_by(user_id=session['user_id'])).all()
    return render_template('accounts.html', accounts=accounts)

@accounts_bp.route('/<int:account_id>')
def view_account(account_id):
    check = check_login()
    if check:
        return check

    # FIXED (PT-01): enforce ownership before returning any account data
    account = db.session.get(Account, account_id)

    if not account or account.user_id != session['user_id']:
        return "Account not found", 404

    transactions = db.session.scalars(select(Transaction).filter(
        or_(Transaction.from_account_id == account_id,
            Transaction.to_account_id == account_id)
    )).all()

    return render_template('account_detail.html',
                         account=account,
                         transactions=transactions)
