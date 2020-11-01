"""Provide routes used to create and revoke access and refresh tokens."""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import (create_access_token, create_refresh_token,
    set_access_cookies, set_refresh_cookies, jwt_refresh_token_required)
from flask_jwt_extended.utils import get_jwt_identity, unset_jwt_cookies
from werkzeug.exceptions import Unauthorized
from heimdall.models.user import User, UserSchema
from http import HTTPStatus


bp = Blueprint('auth', __name__)
user_schema = UserSchema()


@bp.route('/login', methods=['POST'])
def login():
    """Issue authenticated users access and refresh tokens."""
    user = User.query.filter_by(email=request.json.get('email')).first()

    if user is not None and user.authenticate(request.json.get('password')):
        response = jsonify(user_schema.dump(user))
        set_access_cookies(response, create_access_token(identity=user.email))
        set_refresh_cookies(response, create_refresh_token(identity=user.email))
        return response, HTTPStatus.OK

    raise Unauthorized(description='The login attempt failed')


@bp.route('/refresh', methods=['POST'])
@jwt_refresh_token_required
def refresh():
    """Issue an authenticated user a new access token."""
    user = User.query.filter_by(email=get_jwt_identity()).first()

    if user is not None:
        response = jsonify(user_schema.dump(user))
        set_access_cookies(response, create_access_token(identity=user.email))
        return response, HTTPStatus.OK

    # There is no user email associated with that JWT identity
    raise Unauthorized('Unable to retrieve a new access token')


@bp.route('/logout', methods=['DELETE'])
def logout():
    """Revoke the user's access and refresh tokens."""
    response = jsonify(msg='Logout successful')
    unset_jwt_cookies(response)
    return response, HTTPStatus.OK
