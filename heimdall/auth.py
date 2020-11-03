"""
Auth module.

Provides routes used to create, issue, and revoke access and refresh tokens to
authenticated users.
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import (set_access_cookies, set_refresh_cookies,
    create_access_token, create_refresh_token)
from flask_jwt_extended.view_decorators import jwt_refresh_token_required
from flask_jwt_extended.utils import unset_jwt_cookies
from werkzeug.exceptions import Unauthorized
from heimdall.models.user import LoginSchema, User, UserSchema
from http import HTTPStatus
from heimdall import jwt


bp = Blueprint('auth', __name__)
login_schema = LoginSchema()
user_schema = UserSchema()


@jwt.user_identity_loader
def get_jwt_identity(user):
    """
    Return the value to use as the JWT identity.

    This function is called whenever create_access_token is called.
    """
    return user.email


@jwt.user_claims_loader
def get_jwt_claims(user):
    """
    Return the claims that should be added to the JWT token.

    This function is called whenever create_access_token is called.
    """
    return {
        'roles': list(map(lambda r: r.name, user.roles)),
        'permissions': list(map(lambda p: p.name, user.permissions))
    }


@bp.route('/login', methods=['POST'])
def login():
    """Issue authenticated users access and refresh token cookies."""
    login_data = login_schema.load(request.get_json())
    user = User.query.filter_by(email=login_data['email']).first()

    if user is None or not user.authenticate(login_data['password']):
        raise Unauthorized(description='The login attempt failed')

    response = jsonify(user_schema.dump(user))
    set_access_cookies(response, create_access_token(user))
    set_refresh_cookies(response, create_refresh_token(user))
    return response, HTTPStatus.OK


@bp.route('/refresh', methods=['POST'])
@jwt_refresh_token_required
def refresh():
    """Issue an authenticated user a new access token cookie."""
    user = User.query.filter_by(email=get_jwt_identity())

    if user is None:
        # There is no user email associated with that JWT identity
        raise Unauthorized('Unable to retrieve a new access token')

    response = jsonify(user_schema.dump(user))
    set_access_cookies(response, user.create_access_token())
    return response, HTTPStatus.OK


@bp.route('/logout', methods=['DELETE'])
def logout():
    """Revoke the user's access and refresh token cookies."""
    response = jsonify(msg='Logout successful')
    unset_jwt_cookies(response)
    return response, HTTPStatus.OK
