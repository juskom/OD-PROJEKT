import os
from datetime import timedelta

from flask import Flask, request
from flask_login import LoginManager

from .auth import limiter
from .database import db


login_manager = LoginManager()


def create_app():
    app = Flask(__name__)
    app.config.update(
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SQLALCHEMY_DATABASE_URI=os.environ.get('DATABASE_URL'),
        SECRET_KEY=os.environ.get('SECRET_KEY'),
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=10)
    )

    db.init_app(app)
    limiter.init_app(app)

    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint, url_prefix='/auth')


    from .models import User, Note, ConnectorNote

    with app.app_context():
        db.drop_all()
        db.create_all()
        db.session.commit()
        print('Database created')

    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(user_id)

    @app.before_request
    def check_failed_login_attempts_ip():
        ip_address = request.remote_addr
        if auth.is_ip_banned(ip_address):
            error_message = "Zbyt wiele nieudanych prób logowania. Spróbuj ponownie później."
            return error_message, 403



    return app



