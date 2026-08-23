from flask import Blueprint, render_template, request, session, redirect, url_for, flash
from app.database import db
from app.models import Message
from sqlalchemy import select

messages_bp = Blueprint('messages', __name__, url_prefix='/messages')

def check_login():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))
    return None

@messages_bp.route('/')
def index():
    check = check_login()
    if check:
        return check

    messages = db.session.scalars(select(Message).filter_by(user_id=session['user_id'])).all()
    return render_template('messages.html', messages=messages)

@messages_bp.route('/new', methods=['GET', 'POST'])
def new_message():
    check = check_login()
    if check:
        return check

    if request.method == 'POST':
        subject = request.form.get('subject')
        content = request.form.get('content')
        category = request.form.get('category')

        # VULNERABLE: No input sanitization
        # XSS will be stored in database and displayed to admin
        message = Message(
            user_id=session['user_id'],
            subject=subject,
            content=content,
            category=category
        )

        db.session.add(message)
        db.session.commit()

        flash('Message sent successfully!', 'success')
        return redirect(url_for('messages.index'))

    return render_template('new_message.html')

@messages_bp.route('/<int:message_id>')
def view_message(message_id):
    check = check_login()
    if check:
        return check

    message = db.session.get(Message, message_id)

    if not message or (message.user_id != session['user_id'] and not session.get('is_admin')):
        return "Message not found", 404

    # VULNERABLE: Content is directly rendered without escaping
    return render_template('view_message.html', message=message)
