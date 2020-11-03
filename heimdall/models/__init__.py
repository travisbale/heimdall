"""Models package."""

from flask import Blueprint

from heimdall import db

bp = Blueprint("database", __name__)


@bp.after_app_request
def commit_session(response):
    """After each successful request commit the current database session."""
    db.session.commit()
    return response
