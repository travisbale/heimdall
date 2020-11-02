"""Users module."""

from flask import jsonify, request
from flask.views import MethodView
from flask_jwt_extended.utils import unset_jwt_cookies
from flask_jwt_extended.view_decorators import jwt_required
from heimdall.models.user import User, UserSchema
from http import HTTPStatus
from werkzeug.exceptions import Conflict, Forbidden


user_schema = UserSchema()


class UsersResource(MethodView):
    """Dispatches request methods to retrieve or create users."""

    def post(self):
        """Create a new user."""
        user = user_schema.load(request.get_json())

        if User.query.filter_by(email=user.email).count() > 0:
            raise Conflict(description='The user already exists')

        user.save()
        return jsonify(user_schema.dump(user)), HTTPStatus.CREATED


class UserResource(MethodView):
    """Dispatches request methods to delete an existing user."""

    @jwt_required
    def delete(self, id):
        """
        Delete the user with the given ID.

        User accounts are only able to be deleted by the owner of the account.
        """
        # Returning a 404 would create a user enumeration vulnerability
        user = User.query.get(id)

        if user is not None and user.is_current_user():
            user.delete()
            response = jsonify(msg='User has been deleted')
            unset_jwt_cookies(response)
            return response, HTTPStatus.OK

        raise Forbidden(description='The user cannot be deleted')


def register_resources(bp):
    """Add the resource routes to the application blueprint."""
    bp.add_url_rule('/users', view_func=UsersResource.as_view('users_resource'))
    bp.add_url_rule('/users/<int:id>', view_func=UserResource.as_view('user_resource'))
