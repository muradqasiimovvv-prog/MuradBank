from app.routes.auth import auth_bp
from app.routes.dashboard import dashboard_bp
from app.routes.accounts import accounts_bp
from app.routes.transfer import transfer_bp
from app.routes.messages import messages_bp
from app.routes.profile import profile_bp
from app.routes.admin import admin_bp
from app.routes.api import api_bp

__all__ = [
    'auth_bp',
    'dashboard_bp',
    'accounts_bp',
    'transfer_bp',
    'messages_bp',
    'profile_bp',
    'admin_bp',
    'api_bp'
]
