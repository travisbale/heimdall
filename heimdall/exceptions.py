from flask import Blueprint, jsonify, request
from heimdall import jwt
from marshmallow import ValidationError
from werkzeug.exceptions import BadRequest, HTTPException, Unauthorized
from werkzeug.http import HTTP_STATUS_CODES


bp = Blueprint('exceptions', __name__)


@bp.app_errorhandler(HTTPException)
def handle_not_found_exception(exception):
    return _get_response(exception)


@bp.app_errorhandler(ValidationError)
def handle_schema_validation_error(error):
    return _get_response(BadRequest(description=error.messages))


@jwt.expired_token_loader
def handle_expired_token(token):
    return _get_response(Unauthorized(description=f'The {token["type"]} token has expired.'))


@jwt.invalid_token_loader
def handle_invalid_token(message):
    return _get_response(Unauthorized(description=message))


@jwt.unauthorized_loader
def handle_unauthorized_request(message):
    return _get_response(Unauthorized(description=message))


def _get_response(exception):
    return jsonify({
        'statusCode': exception.code,
        'error': HTTP_STATUS_CODES.get(exception.code, 'Unknown error'),
        'message': exception.description
    }), exception.code
