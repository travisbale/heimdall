"""API endpoints for the heimdall service."""

from flask import jsonify, request
from flask.views import MethodView
from flask_jwt_extended.utils import get_jwt_identity, unset_jwt_cookies
from flask_jwt_extended.view_decorators import jwt_required
from marshmallow.exceptions import ValidationError
from heimdall.models.user import User, UserSchema
from http import HTTPStatus
from werkzeug.exceptions import Conflict, BadRequest, Forbidden


user_schema = UserSchema()


class UsersResource(MethodView):
    """Application endpoint for User objects."""

    def post(self):
        """Create a new user account."""
        user = user_schema.load(request.get_json())

        if User.query.filter_by(email=user.email).count() == 0:
            user.save()
            return jsonify(user_schema.dump(user)), HTTPStatus.CREATED
        else:
            raise Conflict(description='The user already exists')


class UserResource(MethodView):
    """Application endpoint for user objects."""

    @jwt_required
    def delete(self, id):
        user = User.query.get(id)

        if user is not None and user.email == get_jwt_identity():
            user.delete()
            response = jsonify(msg='User has been deleted')
            unset_jwt_cookies(response)
            return response, HTTPStatus.OK

        raise Forbidden(description='The user cannot be deleted')


def register_resources(bp):
    bp.add_url_rule('/users', view_func=UsersResource.as_view('users_resource'))
    bp.add_url_rule('/users/<int:id>', view_func=UserResource.as_view('user_resource'))
