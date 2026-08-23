from flask import Flask
from app.config import config
from app.database import db, init_db

def create_app(config_name='development'):
    app = Flask(__name__)
    app.config.from_object(config[config_name])

    # Initialize database
    db.init_app(app)

    # Import models before creating tables
    from app.models import User, Account, Transaction, Message, Beneficiary

    with app.app_context():
        db.create_all()
        from app.database import seed_database
        seed_database()

    # Register blueprints
    from app.routes import auth_bp, dashboard_bp, accounts_bp, transfer_bp, messages_bp, profile_bp, admin_bp, api_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(accounts_bp)
    app.register_blueprint(transfer_bp)
    app.register_blueprint(messages_bp)
    app.register_blueprint(profile_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(api_bp)

    return app
