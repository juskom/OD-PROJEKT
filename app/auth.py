import math
import time
import os
from collections import Counter, defaultdict
import re
from datetime import datetime, timedelta
from functools import wraps
from io import BytesIO
from os import abort

from .database import db
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask import Blueprint, render_template, request, redirect, flash, url_for, current_app, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import bcrypt
import bleach
import pyotp
import pyqrcode
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from Crypto.PublicKey import RSA


from .models import User, Note, ConnectorNote

auth = Blueprint('auth', __name__)

LOGIN_REGEX = r'^[a-zA-Z0-9]+$'
PASSWORD_REGEX = r'^[a-zA-Z0-9!@#$%^&*()_+-=]+$'
STRENGTH_PASSWORD_REGEX = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*(),.?":{}|<>]).{8,}$'
EMAIL_REGEX = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'

pepper = os.getenv('PEPPER')
SERVER_SECRET = os.getenv('SERVER_SECRET')

failed_login_attempts = defaultdict(list)

MAX_FAILED_ATTEMPTS_IP = 5
MAX_TOTAL_FAILED_ATTEMPTS = 10
BLOCK_TIME = timedelta(minutes=5)



limiter = Limiter(
    get_remote_address,
    app=current_app
)

def is_ip_banned(ip_address):
    if ip_address in failed_login_attempts:
        failed_login_attempts[ip_address] = [timestamp for timestamp in failed_login_attempts[ip_address] if datetime.now() - timestamp < BLOCK_TIME]
        if len(failed_login_attempts[ip_address]) >= MAX_FAILED_ATTEMPTS_IP:
            return True
    return False

def update_failed_login_attempts_ip(ip_address):
    failed_login_attempts[ip_address].append(datetime.now())

def reset_failed_login_attempts_ip(ip_address):
    if ip_address in failed_login_attempts:
        failed_login_attempts[ip_address] = []

def totp_verified(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_verified:
            flash("Musisz przejść weryfikację 2FA, aby uzyskać dostęp.", "warning")
            return redirect(url_for('auth.setup_totp'))
        return f(*args, **kwargs)

    return decorated_function

@limiter.limit("5 per minute")
@auth.route('/login')
def login():
    return render_template('login.html')

@limiter.limit("5 per minute")
@auth.route('/login', methods=["POST"])
def login_post():
    time.sleep(1)
    login = bleach.clean(request.form.get("login"))
    password = bleach.clean(request.form.get("password"))
    token = bleach.clean(request.form.get('token'))
    ip_address = request.remote_addr

    user = User.query.filter_by(login=login).first()

    if not user:
        update_failed_login_attempts_ip(ip_address)
        flash("Nieprawidłowy login lub hasło", "warning")
        return redirect(url_for('auth.login'))

    if user.failed_login_attempts >= 5 and user.last_failed_login and datetime.now() - user.last_failed_login < timedelta(minutes=5):
        flash("Za dużo nieudanych prób logowania. Spróbuj ponownie później.", "danger")
        return redirect(url_for('auth.login'))

    if verify_password(password, user.salt, user.password):
        totp_secret = user.totp_secret
        totp = pyotp.TOTP(totp_secret)
        if totp.verify(token, valid_window=1):
            user.failed_login_attempts = 0
            prev_login = user.last_login
            user.last_login = datetime.now()
            db.session.commit()
            reset_failed_login_attempts_ip(ip_address)
            login_user(user)
            flash("Zostałeś zalogowany", "success")
            flash(f"Poprzednie logowanie: {prev_login}", "info")
            return redirect(url_for('main.profile'))
        else:
            update_failed_login_attempts_ip(ip_address)
            user.failed_login_attempts += 1
            user.last_failed_login = datetime.now()
            db.session.commit()
            flash("Nieprawidłowy login lub hasło", "warning")
            return redirect(url_for('auth.login'))
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
@limiter.limit("5/minute")
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

    salt, hashed_password = hash_password(password)
    time.sleep(1)
    private_key, public_key = generate_rsa_keys()
    totp_secret = pyotp.random_base32()
    new_user = User(login=login, email=email, password=hashed_password, salt=salt, private_key=private_key, public_key=public_key, totp_secret=totp_secret)
    db.session.add(new_user)
    db.session.commit()
    login_user(new_user)
    flash("Rejestracja przebiegła pomyślnie. Skonfiguruj 2FA, aby dokończyć proces.", "info")
    return redirect(url_for('auth.setup_totp'))

@auth.route('/setup_totp', methods = ['GET', 'POST'])
@login_required
@limiter.limit("5/minute")
def setup_totp():
    if current_user.is_verified:
        flash("TOTP jest już skonfigurowane", "info")
        return redirect(url_for('main.profile'))

    totp_secret = current_user.totp_secret
    totp = pyotp.TOTP(totp_secret)
    qr_code_url = totp.provisioning_uri(name=current_user.login)
    qr_code = generate_qr_code(qr_code_url)

    if request.method == 'POST':
        totp_code = request.form.get('totp_code')
        if totp.verify(totp_code, valid_window=1):
            current_user.is_verified = True
            db.session.commit()
            flash('TOTP został pomyślnie skonfigurowany!', 'success')
            return redirect(url_for('main.profile'))
        else:
            flash('Niepoprawny kod TOTP', 'danger')
            flash('Skonfiguruj poprawnie TOTP, aby móc się później zalogować', 'warning')

    return render_template("setup_totp.html", qr_code=qr_code, totp_secret=totp_secret)

def generate_qr_code(uri):
    qr_code = pyqrcode.create(uri)
    stream = BytesIO()
    qr_code.svg(stream, scale=5)
    return stream.getvalue().decode('utf-8')

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Zostałeś wylogowany", "info")
    return redirect('/')

@auth.route('/reset_password_request', methods=["GET", "POST"])
@limiter.limit("5/minute")
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('main.profile'))
    if request.method == "POST":
        email = bleach.clean(request.form.get("email"))
        user = User.query.filter_by(email=email).first()
        if user:
            send_reset_password_email(user)
        else:
            update_failed_login_attempts_ip(request.remote_addr)
        flash("Jeśli podany adres e-mail istnieje w bazie, zostanie wysłany link do resetowania hasła", "info")
        return redirect(url_for('auth.login'))
    return render_template('reset_password_request.html')

def send_reset_password_email(user):
    token = generate_reset_password_token(user)
    reset_password_url = url_for('auth.reset_password', token=token, user_id=user.id,_external=True)
    print(f"Reset password URL for {user.login}: {reset_password_url}")

def generate_reset_password_token(user):
    serializer = URLSafeTimedSerializer(current_app.config["SECRET_KEY"])
    token = serializer.dumps(user.email, salt=user.password)

    return token

@auth.route('/reset_password/<token>/<int:user_id>', methods=["GET", "POST"])
def reset_password(token, user_id):
    if current_user.is_authenticated:
        return redirect(url_for('main.profile'))
    user = validate_reset_password_token(token, user_id)
    if not user:
        update_failed_login_attempts_ip(request.remote_addr)
        abort(406, description="Invalid token")

    if request.method == "POST":
        password = bleach.clean(request.form.get("password"))
        password2 = bleach.clean(request.form.get("password2"))

        if password != password2:
            flash("Hasła nie są takie same", "warning")
            return redirect(url_for('auth.reset_password', token=token, user_id=user_id))
        if len(password) < 8:
            flash("Hasło jest za krótkie: min. 8 znaków", "warning")
            return redirect(url_for('auth.reset_password', token=token, user_id=user_id))
        if not re.match(PASSWORD_REGEX, password):
            flash("Hasło zawiera niedozwolone znaki: dozwolone tylko litery, cyfry oraz !@#$%^&*()_+-=", "warning")
            return redirect(url_for('auth.reset_password', token=token, user_id=user_id))
        if not re.match(STRENGTH_PASSWORD_REGEX, password):
            flash("Hasło jest zbyt słabe: musi zawierać przynajmniej jedną dużą literę, jedną małą literę, jedną cyfrę oraz jeden znak specjalny", "warning")
            return redirect(url_for('auth.reset_password', token=token, user_id=user_id))
        salt, hashed_password = hash_password(password)
        time.sleep(1)
        user.password = hashed_password
        user.salt = salt
        db.session.commit()
        flash("Hasło zostało zmienione", "success")
        return redirect(url_for('auth.login'))
    return render_template('reset_password.html', token=token, user_id=user_id)

def validate_reset_password_token(token, user_id):
    user = db.session.query(User).get(user_id)
    if not user:
        return None
    serializer = URLSafeTimedSerializer(current_app.config["SECRET_KEY"])
    try:
        token_user_email = serializer.loads(token, salt=user.password, max_age=120)
    except(BadSignature, SignatureExpired):
        return None
    if user.email != token_user_email:
        return None

    return user


def calculate_entropy(d):
    frequency = Counter(d)
    total_bytes = len(d)
    entropy = 0
    for count in frequency.values():
        probability = count / total_bytes
        if probability > 0:
            entropy -= probability * math.log2(probability)
    return entropy


def hash_password(password: str) -> tuple:
    _password = password.encode()
    _salt = bcrypt.gensalt()
    _hashed_password = bcrypt.hashpw(_password + pepper.encode(), _salt)
    return _salt.decode(), _hashed_password.decode()

def verify_password(password: str, salt: str, stored_hash: str) -> bool:
    _salt = salt.encode()
    _password = password.encode()
    _calculated_hash = bcrypt.hashpw(_password + pepper.encode(), _salt)
    return _calculated_hash.decode() == stored_hash

def generate_rsa_keys():
    rsa_keys = RSA.generate(2048)
    private_key = rsa_keys.export_key(passphrase=SERVER_SECRET, pkcs=8, protection="PBKDF2WithHMAC-SHA512AndAES256-CBC")
    public_key = rsa_keys.publickey().export_key()
    return private_key, public_key

def decrypt_private_key(encrypted_key):
    key = RSA.import_key(encrypted_key, passphrase=SERVER_SECRET)
    return key.export_key()