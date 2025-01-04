import math
import time
from collections import Counter
import re
from copyreg import remove_extension
from datetime import datetime, timedelta
from functools import wraps
from io import BytesIO

from .database import db
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask import Blueprint, render_template, request, redirect, flash, url_for, current_app, session

# from .hello import user_loader
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from passlib.hash import sha256_crypt
import bleach
import pyotp
import pyqrcode
from pyotp import TOTP, random_base32

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
        login_user(user)
        return redirect(url_for('auth.verify_totp'))
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

    #
    totp_secret = pyotp.random_base32()
    new_user.totp_secret = totp_secret
    db.session.add(new_user)
    db.session.commit()
    # totp = pyotp.TOTP(totp_secret)
    # qr_code_url = totp.provisioning_uri(name=login)
    # qr_code = generate_qr_code(qr_code_url)
    #
    db.session.add(new_user)
    db.session.commit()
    login_user(new_user)
    flash("Rejestracja przebiegła pomyślnie. Skonfiguruj 2FA, aby dokończyć proces.", "info")
    return redirect(url_for('auth.setup_totp'))


@auth.route('/setup_totp', methods = ['GET', 'POST'])
@login_required
@limiter.limit("4/minute")
def setup_totp():
    # if current_user.totp_secret:
    #     flash("TOTP jest już skonfigurowane", "info")
    #     return redirect(url_for('main.profile'))
    #
    # totp_secret = pyotp.random_base32()
    # totp = pyotp.TOTP(totp_secret)
    totp_secret = current_user.totp_secret
    totp = pyotp.TOTP(totp_secret)
    qr_code_url = totp.provisioning_uri(name=current_user.login)
    qr_code = generate_qr_code(qr_code_url)

    return render_template("setup_totp.html", qr_code=qr_code, totp_secret=totp_secret)

def generate_qr_code(uri):
    qr_code = pyqrcode.create(uri)
    stream = BytesIO()
    qr_code.svg(stream, scale=5)
    return stream.getvalue().decode('utf-8')

@auth.route('/verify_totp', methods = ['GET', 'POST'])
@login_required
def verify_totp():
    totp_secret = current_user.totp_secret
    totp = pyotp.TOTP(totp_secret)
    if request.method == 'POST':
        token = bleach.clean(request.form.get('token'))
        if totp.verify(token, valid_window=1):
            current_user.is_verified = True
            db.session.commit()
            flash("Zostałeś zalogowany", "success")
            return redirect(url_for('main.profile'))
        else:
            flash("Nieprawidłowy token", "danger")
            return redirect(url_for('auth.verify_totp'))

    return render_template('verify_totp.html')

@auth.route('/logout')
@login_required
def logout():
    current_user.is_verified = False
    db.session.commit()

    logout_user()
    flash("Zostałeś wylogowany", "info")
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

