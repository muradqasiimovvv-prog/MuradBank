from flask import Blueprint, render_template, session, redirect, url_for
from app.models import User, Account, Transaction

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
    accounts = Account.query.filter_by(user_id=session['user_id']).all()
    return render_template('accounts.html', accounts=accounts)

@accounts_bp.route('/<int:account_id>')
def view_account(account_id):
    check = check_login()
    if check:
        return check

    # VULNERABLE: No authorization check!
    # Can access any account by changing account_id
    account = Account.query.get(account_id)

    if not account:
        return "Account not found", 404

    transactions = Transaction.query.filter(
        (Transaction.from_account_id == account_id) |
        (Transaction.to_account_id == account_id)
    ).all()

    return render_template('account_detail.html',
                         account=account,
                         transactions=transactions)
