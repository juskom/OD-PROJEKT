from sqlalchemy import func
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from .database import db

# Model użytkownika
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)  # Hashed password
    totp_secret = db.Column(db.String(100))  # Secret for TOTP
    last_failed_login = db.Column(db.DateTime, nullable=True)
    last_login = db.Column(db.DateTime, default=func.now())
    failed_login_attempts = db.Column(db.Integer, default=0)

    # Relacja do notatek
    notes = db.relationship('Note', backref='author', lazy=True)
    shared_notes = db.relationship('ConnectorNote', backref='user', lazy=True)

# Model notatki
class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    text = db.Column(db.Text, nullable=False)
    is_public = db.Column(db.Boolean, default=False)
    is_encrypted = db.Column(db.Boolean, default=False)
    encryption_key = db.Column(db.String(200), nullable=True)
    signature = db.Column(db.String(200), nullable=True)
    # Relacja z użytkownikami
    userID = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Model dla połączeń notatek z użytkownikami (udostępnianie notatek)
class ConnectorNote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    userID = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    noteID = db.Column(db.Integer, db.ForeignKey('note.id'), nullable=False)
