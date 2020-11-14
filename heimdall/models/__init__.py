"""Models package."""

from flask import Blueprint

from heimdall import db

bp = Blueprint("database", __name__)


@bp.after_app_request
def commit_session(response):
    """After each successful request commit the current database session."""
    if response.status_code < 400:
        # TODO: Might have to catch exceptions here
        db.session.commit()

    return response
