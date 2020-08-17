"""Initialize the heimdall service."""

from flask import Flask


def create_app(config='heimdall.config.Config'):
    """Create and configure an instance of the Flask application."""
    app = Flask(__name__, instance_relative_config=True)

    app.config.from_object(config)

    _register_blueprints(app)

    return app


def _register_blueprints(app):
    from heimdall import resources

    app.register_blueprint(resources.bp, url_prefix='/api/v1')
