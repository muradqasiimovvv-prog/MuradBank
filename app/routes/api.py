from flask import Blueprint, request, session, jsonify
from app.database import db
from app.models import Transaction, Account
from sqlalchemy import select

api_bp = Blueprint('api', __name__, url_prefix='/api')

@api_bp.route('/search-transactions', methods=['POST'])
def search_transactions():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    search_term = request.form.get('q', '')

    # FIXED (PT-02): use the ORM query builder instead of raw SQL so all
    # values are automatically parameterized — eliminates SQL injection
    # regardless of what the user submits in `search_term`.
    transactions = db.session.scalars(
        select(Transaction)
        .filter(Transaction.user_id == session['user_id'])
        .filter(Transaction.description.ilike(f'%{search_term}%'))
    ).all()

    return jsonify({'transactions': [
        {
            'id': t.id,
            'from_account_id': t.from_account_id,
            'to_account_id': t.to_account_id,
            'amount': t.amount,
            'description': t.description
        }
        for t in transactions
    ]})

@api_bp.route('/account-info/<account_id>', methods=['GET'])
def get_account_info(account_id):
    """VULNERABLE: IDOR via API"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    # FIXED (PT-01): enforce ownership before returning any account data
    account = db.session.get(Account, account_id)

    if not account or account.user_id != session['user_id']:
        return jsonify({'error': 'Account not found'}), 404

    return jsonify({
        'id': account.id,
        'account_number': account.account_number,
        'balance': account.balance,
        'owner_id': account.user_id,
        'status': account.status
    })
