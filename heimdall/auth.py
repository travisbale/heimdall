"""Provide routes used to create and revoke access and refresh tokens."""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import set_access_cookies, set_refresh_cookies
from flask_jwt_extended.view_decorators import jwt_refresh_token_required
from flask_jwt_extended.utils import unset_jwt_cookies
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
        set_access_cookies(response, user.create_access_token())
        set_refresh_cookies(response, user.create_refresh_token())
        return response, HTTPStatus.OK

    raise Unauthorized(description='The login attempt failed')


@bp.route('/refresh', methods=['POST'])
@jwt_refresh_token_required
def refresh():
    """Issue an authenticated user a new access token."""
    user = User.get_current_user()

    if user is not None:
        response = jsonify(user_schema.dump(user))
        set_access_cookies(response, user.create_access_token())
        return response, HTTPStatus.OK

    # There is no user email associated with that JWT identity
    raise Unauthorized('Unable to retrieve a new access token')


@bp.route('/logout', methods=['DELETE'])
def logout():
    """Revoke the user's access and refresh tokens."""
    response = jsonify(msg='Logout successful')
    unset_jwt_cookies(response)
    return response, HTTPStatus.OK
