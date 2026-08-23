from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from app.database import db
from app.models import User
from sqlalchemy import select

auth_bp = Blueprint('auth', __name__, url_prefix='/')

@auth_bp.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard.index'))
    return render_template('landing.html')

@auth_bp.route('/index')
def index_old():
    return redirect(url_for('auth.login'))

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # VULNERABLE: No rate limiting, brute force possible
        user = db.session.scalar(select(User).filter_by(username=username))

        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = user.is_admin
            return redirect(url_for('dashboard.index'))
        else:
            flash('Invalid username or password', 'danger')

    return render_template('login.html')

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        full_name = request.form.get('full_name')

        if db.session.scalar(select(User).filter_by(username=username)):
            flash('Username already exists', 'danger')
            return redirect(url_for('auth.register'))

        if db.session.scalar(select(User).filter_by(email=email)):
            flash('Email already exists', 'danger')
            return redirect(url_for('auth.register'))

        # VULNERABLE: No input validation, weak password check
        user = User(username=username, email=email, full_name=full_name)
        user.set_password(password)

        db.session.add(user)
        db.session.commit()

        flash('Account created! You can now login.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('register.html')

@auth_bp.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('auth.login'))
