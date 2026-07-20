# app.py
import os
from dotenv import load_dotenv
from flask import Flask, redirect, url_for
from extensions import db
from errors import register_error_handlers
from auth import register_auth_check
from api.v1 import v1
from api.ui import ui


def _require_secret(name, value, min_length=8):
    if not value or len(value) < min_length:
        raise RuntimeError(f"{name} must be set to a value of at least {min_length} characters")


def create_app():
    load_dotenv()

    app = Flask(__name__)

    # set variables
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
    app.config['UPLOAD_TOKEN'] = os.getenv('UPLOAD_TOKEN')
    app.config['ADMIN_PASSWORD'] = os.getenv('ADMIN_PASSWORD')

    _require_secret('UPLOAD_TOKEN', app.config['UPLOAD_TOKEN'])
    _require_secret('ADMIN_PASSWORD', app.config['ADMIN_PASSWORD'])

    # register blueprints
    app.register_blueprint(v1, url_prefix='/v1')
    app.register_blueprint(ui, url_prefix='/ui')

    # initialize database
    db.init_app(app)

    # initialize models
    with app.app_context():
        db.create_all()
        register_error_handlers(app)
        register_auth_check(app)

    @app.route("/", methods=['GET'])
    def home():
        return redirect(url_for('ui.splash'))

    @app.route("/health", methods=['GET'])
    def health():
        return "OK"

    return app


if __name__ == '__main__':
    flask_app = create_app()
    flask_app.run()
