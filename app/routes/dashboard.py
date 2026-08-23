from flask import Blueprint, render_template, session, redirect, url_for
from app.models import User, Account, Transaction

dashboard_bp = Blueprint('dashboard', __name__, url_prefix='/dashboard')

def check_login():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))
    return None

@dashboard_bp.route('/')
def index():
    check = check_login()
    if check:
        return check

    user = User.query.get(session['user_id'])
    accounts = Account.query.filter_by(user_id=session['user_id']).all()
    transactions = Transaction.query.filter_by(user_id=session['user_id']).all()

    total_balance = sum(acc.balance for acc in accounts)

    return render_template('dashboard.html',
                         user=user,
                         accounts=accounts,
                         transactions=transactions,
                         total_balance=total_balance)
