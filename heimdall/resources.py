"""API endpoints for the heimdall service."""

from flask import Blueprint, request
from flask_jwt_extended.utils import get_jwt_identity
from flask_jwt_extended.view_decorators import jwt_required
from flask_restful import Api, Resource
from marshmallow.exceptions import ValidationError
from heimdall.models import User, UserSchema
from http import HTTPStatus


bp = Blueprint('api', __name__)
api = Api(bp)

user_schema = UserSchema()

@api.resource('/users')
class UsersResource(Resource):
    """Application endpoint for User objects."""

    def post(self):
        """Create a new user account."""
        try:
            user = user_schema.load(request.get_json())

            if User.query.filter_by(email=user.email).count() == 0:
                user.save()
                return user_schema.dump(user), HTTPStatus.CREATED
            else:
                return {'msg': 'Email has already been registered'}, HTTPStatus.CONFLICT

        except ValidationError as e:
            return e.messages, HTTPStatus.BAD_REQUEST


@api.resource('/users/<int:id>', endpoint='user')
class UserResource(Resource):
    """Application endpoint for user objects."""

    @jwt_required
    def delete(self, id):
        user = User.query.get(id)

        if user is not None and user.email == get_jwt_identity():
            user.delete()
            return {'msg': 'User has been deleted'}, HTTPStatus.OK

        return {'msg': 'Cannot delete user'}, HTTPStatus.FORBIDDEN
