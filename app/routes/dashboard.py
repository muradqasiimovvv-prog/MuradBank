from flask import Blueprint, render_template, session, redirect, url_for
from app.database import db
from app.models import User, Account, Transaction
from sqlalchemy import select

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

    user = db.session.get(User, session['user_id'])
    accounts = db.session.scalars(select(Account).filter_by(user_id=session['user_id'])).all()
    transactions = db.session.scalars(select(Transaction).filter_by(user_id=session['user_id'])).all()

    total_balance = sum(acc.balance for acc in accounts)

    return render_template('dashboard.html',
                         user=user,
                         accounts=accounts,
                         transactions=transactions,
                         total_balance=total_balance)
