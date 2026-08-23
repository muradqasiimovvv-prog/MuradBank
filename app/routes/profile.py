from flask import Blueprint, render_template, request, session, redirect, url_for, flash, current_app
from app.database import db
from app.models import User
from werkzeug.utils import secure_filename
import os

profile_bp = Blueprint('profile', __name__, url_prefix='/profile')

def check_login():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))
    return None

@profile_bp.route('/')
def index():
    check = check_login()
    if check:
        return check

    user = User.query.get(session['user_id'])
    return render_template('profile.html', user=user)

@profile_bp.route('/edit', methods=['GET', 'POST'])
def edit():
    check = check_login()
    if check:
        return check

    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        user.full_name = request.form.get('full_name')
        user.phone = request.form.get('phone')

        # Handle file upload
        if 'avatar' in request.files:
            file = request.files['avatar']

            if file and file.filename != '':
                # VULNERABLE: No file type validation!
                # VULNERABLE: Using filename directly (directory traversal possible)
                filename = secure_filename(file.filename)
                upload_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)

                # Create upload folder if not exists
                os.makedirs(current_app.config['UPLOAD_FOLDER'], exist_ok=True)

                file.save(upload_path)
                user.avatar = filename

        db.session.commit()
        flash('Profile updated!', 'success')
        return redirect(url_for('profile.index'))

    return render_template('edit_profile.html', user=user)

@profile_bp.route('/uploads/<filename>')
def get_upload(filename):
    """Serve uploaded files"""
    # VULNERABLE: Can read any file from uploads folder
    upload_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(upload_path):
        with open(upload_path, 'rb') as f:
            return f.read()
    return "File not found", 404
