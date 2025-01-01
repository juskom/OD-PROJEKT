import math
import time
from collections import Counter
import re
from copyreg import remove_extension
from datetime import datetime, timedelta

from .database import db
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask import Blueprint, render_template, request, redirect, flash, url_for, current_app

# from .hello import user_loader
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from passlib.hash import sha256_crypt
import bleach

from .models import User, Note, ConnectorNote

auth = Blueprint('auth', __name__)

LOGIN_REGEX = r'^[a-zA-Z0-9]+$'
PASSWORD_REGEX = r'^[a-zA-Z0-9!@#$%^&*()_+-=]+$'
STRENGTH_PASSWORD_REGEX = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*(),.?":{}|<>]).{8,}$'
EMAIL_REGEX = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'

limiter = Limiter(
    get_remote_address,
    app=current_app
)

@auth.route('/login')
def login():
    return render_template('login.html')

@auth.route('/login', methods=["POST"])
def login_post():
    time.sleep(1)
    login = bleach.clean(request.form.get("login"))
    password = bleach.clean(request.form.get("password"))
    user = User.query.filter_by(login=login).first()

    if not user:
        flash("Nieprawidłowy login lub hasło", "warning")
        return redirect(url_for('auth.login'))

    if user.failed_login_attempts >= 5 and user.last_failed_login and datetime.now() - user.last_failed_login < timedelta(minutes=5):
        flash("Za dużo nieudanych prób logowania. Spróbuj ponownie później.", "danger")
        return redirect(url_for('auth.login'))

    if sha256_crypt.verify(password, user.password):
        user.failed_login_attempts = 0
        user.last_login = datetime.now()
        db.session.commit()
        login_user(user, remember=True)
        return redirect(url_for('main.profile'))
    else:
        user.failed_login_attempts += 1
        user.last_failed_login = datetime.now()
        db.session.commit()
        flash("Nieprawidłowy login lub hasło", "warning")
        return redirect(url_for('auth.login'))


@auth.route('/register')
def register():
    return render_template('register.html')

@auth.route('/register', methods=["POST"])
@limiter.limit("4/minute")
def register_post():
    error = False
    login = bleach.clean(request.form.get("login"))
    email = bleach.clean(request.form.get("email"))
    password = bleach.clean(request.form.get("password"))
    password2 = bleach.clean(request.form.get("password2"))

    if len(login) < 3:
        error = True
        flash("Login jest za krótki: min. 3 znaki", "warning")

    if password != password2:
        error = True
        flash("Hasła nie są takie same", "warning")

    if len(password) < 8:
        error = True
        flash("Hasło jest za krótkie: min. 8 znaków", "warning")

    if not re.match(LOGIN_REGEX, login):
        error = True
        flash("Login zawiera niedozwolone znaki: dozwolone tylko litery i cyfry", "warning")

    if not re.match(EMAIL_REGEX, email):
        error = True
        flash("Nieprawidłowy format adresu email", "warning")

    if not re.match(PASSWORD_REGEX, password):
        error = True
        flash("Hasło zawiera niedozwolone znaki: dozwolone tylko litery, cyfry oraz !@#$%^&*()_+-=", "warning")

    if not re.match(STRENGTH_PASSWORD_REGEX, password):
        error = True
        flash("Hasło jest zbyt słabe: musi zawierać przynajmniej jedną dużą literę, jedną małą literę, jedną cyfrę oraz jeden znak specjalny", "warning")

    if error:
        return redirect(url_for('auth.register'))

    user = User.query.filter((User.login == login) | (User.email == email)).first()
    if user:
        flash("Użytkownik o takim loginie lub e-mailu już istnieje", "warning")
        return redirect(url_for('auth.register'))

    hashed_password = sha256_crypt.hash(password)
    new_user = User(login=login, email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    flash("Rejestracja przebiegła pomyślnie", "success")
    return redirect(url_for('auth.login'))


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/')

def calculate_entropy(d):
    frequency = Counter(d)
    total_bytes = len(d)
    entropy = 0
    for count in frequency.values():
        probability = count / total_bytes
        if probability > 0:
            entropy -= probability * math.log2(probability)
    return entropy

