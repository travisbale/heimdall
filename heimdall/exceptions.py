"""Exceptions module."""

from flask import Blueprint, jsonify
from marshmallow import ValidationError
from werkzeug.exceptions import BadRequest, HTTPException, Unauthorized
from werkzeug.http import HTTP_STATUS_CODES

from . import jwt

bp = Blueprint('exceptions', __name__)


@bp.app_errorhandler(HTTPException)
def handle_generic_http_exception(exception):
    """Handle generic HTTP exceptions."""
    return _get_response(exception)


@bp.app_errorhandler(ValidationError)
def handle_schema_validation_error(error):
    """Handle schema validation errors raised by marshmallow."""
    return _get_response(BadRequest(description=error.messages))


@jwt.expired_token_loader
def handle_expired_token(token):
    """
    Handle expired token errors.

    Triggered when an expired JWT attempts to access a protected endpoint.
    """
    return _get_response(Unauthorized(description=f'The {token["type"]} token has expired.'))


@jwt.invalid_token_loader
def handle_invalid_token(message):
    """
    Handle invalid token errors.

    Triggered when an invalid JWT attempts to access a protected endpoint.
    """
    return _get_response(Unauthorized(description=message))


@jwt.unauthorized_loader
def handle_unauthorized_request(message):
    """
    Handle unauthorized request errors.

    Triggered when a request to a protected endpoint does not contain a JWT.
    """
    return _get_response(Unauthorized(description=message))


def _get_response(exception):
    """
    Return a JSON Flask response object.

    The properties of the JSON object and the status code of the result are set
    based on the details of the exception.
    """
    return jsonify({
        'statusCode': exception.code,
        'error': HTTP_STATUS_CODES.get(exception.code, 'Unknown error'),
        'message': exception.description
    }), exception.code
