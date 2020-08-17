"""Initialize the heimdall service."""

from flask import Flask
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy


db = SQLAlchemy()
migrate = Migrate()


def create_app(config='heimdall.config.Config'):
    """Create and configure an instance of the Flask application."""
    app = Flask(__name__, instance_relative_config=True)

    app.config.from_object(config)

    _initialize_extensions(app)
    _register_blueprints(app)

    return app


def _initialize_extensions(app):
    db.init_app(app)
    migrate.init_app(app, db)


def _register_blueprints(app):
    from heimdall import resources

    app.register_blueprint(resources.bp, url_prefix='/api/v1')
