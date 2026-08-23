from flask import Blueprint, request, session, jsonify
from app.database import db
from app.models import Transaction

api_bp = Blueprint('api', __name__, url_prefix='/api')

@api_bp.route('/search-transactions', methods=['POST'])
def search_transactions():
    """VULNERABLE: SQL Injection"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    search_term = request.form.get('q', '')

    # VULNERABLE: Raw SQL with user input!
    # No parameterized queries, direct concatenation
    query = f"""
        SELECT * FROM transactions
        WHERE user_id = {session['user_id']}
        AND description LIKE '%{search_term}%'
    """

    try:
        result = db.session.execute(query)
        rows = result.fetchall()

        transactions = []
        for row in rows:
            transactions.append({
                'id': row[0],
                'from_account_id': row[1],
                'to_account_id': row[2],
                'amount': row[4],
                'description': row[5]
            })

        return jsonify({'transactions': transactions})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/account-info/<account_id>', methods=['GET'])
def get_account_info(account_id):
    """VULNERABLE: IDOR via API"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    # VULNERABLE: No authorization check!
    from app.models import Account
    account = Account.query.get(account_id)

    if not account:
        return jsonify({'error': 'Account not found'}), 404

    return jsonify({
        'id': account.id,
        'account_number': account.account_number,
        'balance': account.balance,
        'owner_id': account.user_id,
        'status': account.status
    })
