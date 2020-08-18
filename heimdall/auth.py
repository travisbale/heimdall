"""Provide routes used to create and revoke access and refresh tokens."""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import (create_access_token, create_refresh_token,
    set_access_cookies, set_refresh_cookies)
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
