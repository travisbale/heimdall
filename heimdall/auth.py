"""Provide routes used to create and revoke access and refresh tokens."""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import (create_access_token, create_refresh_token,
    set_access_cookies, set_refresh_cookies, jwt_refresh_token_required)
from flask_jwt_extended.utils import get_jwt_identity, unset_jwt_cookies
from heimdall.models import User
from http import HTTPStatus


bp = Blueprint('auth', __name__)


@bp.route('/login', methods=['POST'])
def login():
    """Issue authenticated users access and refresh tokens."""
    user = User.query.filter_by(email=request.json.get('email')).first()

    if user is not None and user.authenticate(request.json.get('password')):
        response = jsonify({'msg': 'login successful'})
        set_access_cookies(response, create_access_token(identity=user.email))
        set_refresh_cookies(response, create_refresh_token(identity=user.email))
        return response, HTTPStatus.OK

    return jsonify({'msg': 'login failed'}), HTTPStatus.UNAUTHORIZED


@bp.route('/refresh', methods=['POST'])
@jwt_refresh_token_required
def refresh():
    """Issue an authenticated user a new access token."""
    email = get_jwt_identity()
    response = jsonify({'msg': 'refresh successful'})
    set_access_cookies(response, create_access_token(identity=email))
    return response, HTTPStatus.OK


@bp.route('/logout', methods=['DELETE'])
def logout():
    """Revoke the user's access and refresh tokens."""
    response = jsonify({'msg': 'logout successful'})
    unset_jwt_cookies(response)
    return response, HTTPStatus.OK
