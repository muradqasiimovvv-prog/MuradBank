from flask import Blueprint, render_template, request, session, redirect, url_for, flash, current_app, send_from_directory
from app.database import db
from app.models import User
from werkzeug.utils import secure_filename
from PIL import Image
import os

profile_bp = Blueprint('profile', __name__, url_prefix='/profile')

def allowed_file(filename):
    """FIXED (PT-06): enforce the image-only extension allow-list."""
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in current_app.config['ALLOWED_EXTENSIONS']

def is_genuine_image(file_stream):
    """FIXED (PT-06): verify the file is actually a valid image, not just
    named like one — catches a renamed .html/.php file, defense in depth
    beyond the extension check."""
    try:
        file_stream.seek(0)
        Image.open(file_stream).verify()
        file_stream.seek(0)
        return True
    except Exception:
        return False

def check_login():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))
    return None

@profile_bp.route('/')
def index():
    check = check_login()
    if check:
        return check

    user = db.session.get(User, session['user_id'])
    return render_template('profile.html', user=user)

@profile_bp.route('/edit', methods=['GET', 'POST'])
def edit():
    check = check_login()
    if check:
        return check

    user = db.session.get(User, session['user_id'])

    if request.method == 'POST':
        user.full_name = request.form.get('full_name')
        user.phone = request.form.get('phone')

        # Handle file upload
        if 'avatar' in request.files:
            file = request.files['avatar']

            if file and file.filename != '':
                # FIXED (PT-06): extension allow-list + real image-content check
                if not allowed_file(file.filename):
                    flash('Invalid file type. Only JPG, PNG, and GIF images are allowed.', 'danger')
                    return redirect(url_for('profile.edit'))

                if not is_genuine_image(file.stream):
                    flash('File is not a valid image.', 'danger')
                    return redirect(url_for('profile.edit'))

                filename = secure_filename(file.filename)
                upload_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)

                os.makedirs(current_app.config['UPLOAD_FOLDER'], exist_ok=True)

                file.save(upload_path)
                user.avatar = filename

        db.session.commit()
        flash('Profile updated!', 'success')
        return redirect(url_for('profile.index'))

    return render_template('edit_profile.html', user=user)

@profile_bp.route('/uploads/<filename>')
def get_upload(filename):
    # FIXED (PT-06): send_from_directory safely resolves the path within
    # UPLOAD_FOLDER and rejects traversal attempts, instead of manually
    # joining an unsanitized filename onto the filesystem path.
    return send_from_directory(current_app.config['UPLOAD_FOLDER'], filename)
