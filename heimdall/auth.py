"""
Auth module.

Provides routes used to create, issue, and revoke access and refresh tokens to
authenticated users.
"""

import json
import os
from http import HTTPStatus

from flask import Blueprint, jsonify, request
from flask_jwt_extended import create_access_token, create_refresh_token, set_access_cookies, set_refresh_cookies
from flask_jwt_extended.utils import get_jwt_identity, unset_jwt_cookies
from flask_jwt_extended.view_decorators import jwt_required
from itsdangerous import BadSignature, URLSafeSerializer
from werkzeug.exceptions import BadRequest, Conflict, Unauthorized

from . import jwt
from .models.role import Role
from .models.role_assignment import RoleAssignment
from .models.user import LoginSchema, RegistrationSchema, User, UserSchema

bp = Blueprint("auth", __name__)
login_schema = LoginSchema()
user_schema = UserSchema()
registration_schema = RegistrationSchema()

serializer = URLSafeSerializer(os.getenv("SECRET_KEY"), os.getenv("HASH_SALT"))


@jwt.user_identity_loader
def get_user_jwt_identity(user):
    """
    Return the value to use as the JWT identity.

    This function is called whenever create_access_token is called.
    """
    return user.email


@jwt.additional_claims_loader
def add_claims_to_jwt_token(user):
    """
    Return the claims that should be added to the JWT token.

    This function is called whenever create_access_token is called.
    """
    return {
        "roles": list(map(lambda r: r.name, user.roles)),
        "permissions": list(map(lambda p: p.name, user.permissions)),
    }


@bp.route("/register", methods=["POST"])
def register():
    """Create a new user account from the issued token and user password."""
    registration_data = registration_schema.load(request.get_json())

    try:
        user_data = json.loads(serializer.loads(registration_data["token"]))
    except BadSignature:
        raise BadRequest(description="The token was invalid")

    if User.query.filter_by(email=user_data["email"]).count() > 0:
        raise Conflict(description="An account with this email address has already been registered")

    user = User(user_data["email"], registration_data["password"]).save()

    for role_name in user_data["roles"]:
        # Assign the user the roles they were given
        role = Role.query.filter_by(name=role_name).one()
        RoleAssignment(user.id, role.id).save()

    response = jsonify(user_schema.dump(user))
    set_access_cookies(response, create_access_token(user))
    set_refresh_cookies(response, create_refresh_token(user))
    return response, HTTPStatus.OK


@bp.route("/login", methods=["POST"])
def login():
    """Issue authenticated users access and refresh token cookies."""
    login_data = login_schema.load(request.get_json())
    user = User.query.filter_by(email=login_data["email"]).first()

    if user is None or not user.authenticate(login_data["password"]):
        raise Unauthorized(description="Incorrect username or password")

    response = jsonify(user_schema.dump(user))
    set_access_cookies(response, create_access_token(user))
    set_refresh_cookies(response, create_refresh_token(user))
    return response, HTTPStatus.OK


@bp.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    """Issue an authenticated user a new access token cookie."""
    user = User.query.filter_by(email=get_jwt_identity()).first()

    if user is None:
        # There is no user email associated with that JWT identity
        raise Unauthorized("Unable to retrieve a new access token")

    response = jsonify(user_schema.dump(user))
    set_access_cookies(response, create_access_token(user))
    return response, HTTPStatus.OK


@bp.route("/logout", methods=["DELETE"])
def logout():
    """Revoke the user's access and refresh token cookies."""
    response = jsonify(msg="Logout successful")
    unset_jwt_cookies(response)
    return response, HTTPStatus.OK
