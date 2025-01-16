from datetime import datetime
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from .database import db


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    salt = db.Column(db.String())
    totp_secret = db.Column(db.String(100))
    last_failed_login = db.Column(db.DateTime, nullable=True)
    last_login = db.Column(db.DateTime, default=datetime.now())
    failed_login_attempts = db.Column(db.Integer, default=0)
    is_verified = db.Column(db.Boolean, default=False)
    public_key = db.Column(db.String(200), nullable=True)
    private_key = db.Column(db.String(200), nullable=True)
    notes = db.relationship('Note', backref='author', lazy=True)
    shared_notes = db.relationship('ConnectorNote', backref='user', lazy=True)



class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(), nullable=False)
    text = db.Column(db.String(), nullable=False)
    is_public = db.Column(db.Boolean, default=False)
    is_encrypted = db.Column(db.Boolean, default=False)
    signature = db.Column(db.String(200), nullable=True)
    userID = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_shared = db.Column(db.Boolean, default=False)

class ConnectorNote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    userID = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    noteID = db.Column(db.Integer, db.ForeignKey('note.id'), nullable=False)


# class ResetPasswordToken(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     token = db.Column(db.String(200), nullable=False)
#     timestamp = db.Column(db.DateTime, default=datetime.now, nullable=False)
#     expiration = db.Column(db.DateTime, nullable=False)
#     user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
#     user = db.relationship('User', backref='reset_password_token')
