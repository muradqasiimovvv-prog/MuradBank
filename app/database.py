from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

def init_db(app):
    db.init_app(app)
    with app.app_context():
        db.create_all()  # Create tables first
        seed_database()  # Then seed data

def seed_database():
    """Seed database with demo users and accounts"""
    from app.models import User, Account, Transaction
    from sqlalchemy import select

    # Check if database is already seeded
    try:
        user_count = db.session.scalar(select(User).limit(1))
        if user_count:
            return  # Database already seeded
    except Exception:
        pass  # Table doesn't exist, proceed with seeding

    # Demo users
    user1 = User(username='alice', email='alice@muradbank.local', full_name='Alice Johnson')
    user1.set_password('password123')
    user1.is_admin = False

    user2 = User(username='bob', email='bob@muradbank.local', full_name='Bob Smith')
    user2.set_password('password123')
    user2.is_admin = False

    admin = User(username='admin', email='admin@muradbank.local', full_name='Admin User')
    admin.set_password('admin123')
    admin.is_admin = True

    db.session.add_all([user1, user2, admin])
    db.session.commit()

    # Demo accounts
    account1 = Account(user_id=user1.id, account_number='1001234567890', balance=5000.00)
    account2 = Account(user_id=user2.id, account_number='1002234567890', balance=3000.00)
    account3 = Account(user_id=admin.id, account_number='1003234567890', balance=10000.00)

    db.session.add_all([account1, account2, account3])
    db.session.commit()

    # Demo transaction
    transaction = Transaction(
        from_account_id=account1.id,
        to_account_id=account2.id,
        user_id=user1.id,
        amount=500.00,
        description='Payment for services'
    )
    db.session.add(transaction)
    db.session.commit()
