"""Users module."""

from heimdall.resources.view_decorators import permission_required
from flask import jsonify, request
from flask.views import MethodView
from flask_jwt_extended.utils import unset_jwt_cookies
from heimdall.models.user import User, UserSchema
from http import HTTPStatus
from werkzeug.exceptions import Conflict


user_schema = UserSchema()


class UsersResource(MethodView):
    """Dispatches request methods to retrieve or create users."""

    @permission_required('create:users')
    def post(self):
        """Create a new user."""
        user = user_schema.load(request.get_json())

        if User.query.filter_by(email=user.email).count() > 0:
            raise Conflict(description='The user already exists')

        user.save()
        return jsonify(user_schema.dump(user)), HTTPStatus.CREATED


class UserResource(MethodView):
    """Dispatches request methods to delete an existing user."""

    @permission_required('delete:users')
    def delete(self, id):
        """Delete the user with the given ID."""
        user = User.query.get_or_404(id, 'The user does not exist')
        user.delete()
        response = jsonify(message='The user has been deleted')
        unset_jwt_cookies(response)
        return response, HTTPStatus.OK


def register_resources(bp):
    """Add the resource routes to the application blueprint."""
    bp.add_url_rule('/users', view_func=UsersResource.as_view('users_resource'))
    bp.add_url_rule('/users/<int:id>', view_func=UserResource.as_view('user_resource'))
