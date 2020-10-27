"""Initialize the heimdall service."""

import os

from flask import Flask
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy


db = SQLAlchemy()
migrate = Migrate()
jwt = JWTManager()


def create_app(config='heimdall.config.Config'):
    """Create and configure an instance of the Flask application."""
    app = Flask(__name__, instance_relative_config=True)

    app.config.from_object(config)

    CORS(app, origins=os.getenv('CORS_ORIGIN'), supports_credentials=True)

    _initialize_extensions(app)
    _register_blueprints(app)

    return app


def _initialize_extensions(app):
    # Initialize SQL alchemy and the migration engine
    db.init_app(app)
    migrate.init_app(app, db)

    # Initialize JSON web tokens
    jwt.init_app(app)


def _register_blueprints(app):
    from heimdall import auth, resources

    app.register_blueprint(auth.bp)
    app.register_blueprint(resources.bp, url_prefix='/v1')
