"""Initialize the heimdall service."""

from flask import Flask


def create_app():
    """Create and configure an instance of the Flask application."""
    app = Flask(__name__, instance_relative_config=True)

    register_blueprints(app)

    return app


def register_blueprints(app):
    """Register REST API endpoints."""
    from heimdall import resources

    app.register_blueprint(resources.bp, url_prefix='/api/v1')
