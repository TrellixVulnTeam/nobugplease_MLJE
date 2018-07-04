from flask_sqlalchemy import SQLAlchemy
from flask import Flask, session
from flask_bootstrap import Bootstrap
from flask_login.login_manager import LoginManager
from config import config
from random import randint
from flask_mail import Mail

db = SQLAlchemy()
bootstrap = Bootstrap()
login_manager = LoginManager()
mail = Mail()

from app.models import User, AnonymousUser
login_manager.session_protection = 'strong'
login_manager.login_view = 'page.page_login'
login_manager.anonymous_user = AnonymousUser


def create_app(config_name):
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    db.init_app(app)
    bootstrap.init_app(app)
    mail.init_app(app)

    from app.main import page as page_blueprint
    app.register_blueprint(page_blueprint)

    # @app.before_request
    # def crsf_protect():
    #     if request.method == 'POST':
    #         token = session.pop('_csrf_token', None)
    #         if not token or token != request.form.get('_csrf_token'):
    #             abort(403)
    #
    def generate_csrf_token():
        if '_csrf_token' not in session:
            random_string = ''
            for i in range(39):
                random_string += str(randint(0,10))
            session['_csrf_token'] = random_string
        return session['_csrf_token']

    app.jinja_env.globals['csrf_token'] = generate_csrf_token

    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(id):
        return User.query.get(id)


    return app
