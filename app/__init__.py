from flask import Flask
from flask_login import LoginManager
from flask_migrate import Migrate
# from app.config import Config
from .database import db

login_manager = LoginManager()


def create_app():
    app = Flask(__name__)
    migrate = Migrate(app, db)
    # app.config['SECRET_KEY'] = Config.SECRET_KEY
    # app.config['SQLALCHEMY_DATABASE_URI'] = Config.SQLALCHEMY_DATABASE_URL

    app.config['SECRET_KEY'] = "206363ef77d567cc511df5098695d2b85058952afd5e2b1eecd5aed981805e60"
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sqlite3.db'

    db.init_app(app)

    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint, url_prefix='/auth')

    from .models import User, Note, ConnectorNote

    with app.app_context():
        db.create_all()
        print('Database created')

    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(user_id)

    return app


