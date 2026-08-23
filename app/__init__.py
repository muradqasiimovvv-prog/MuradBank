from flask import Flask
from flask_wtf import CSRFProtect
from app.config import config
from app.database import db, init_db

csrf = CSRFProtect()

def create_app(config_name='development'):
    app = Flask(__name__)
    app.config.from_object(config[config_name])

    # FIXED (PT-05): apply CSRF protection to every state-changing request
    # app-wide, instead of only the transfer form.
    csrf.init_app(app)

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

    # FIXED (PT-08): never leak stack traces/SQL/internal paths to the client,
    # even if debug mode is ever accidentally left on.
    @app.errorhandler(500)
    def internal_error(error):
        app.logger.exception('Unhandled server error')
        return {'error': 'An unexpected error occurred'}, 500

    return app
