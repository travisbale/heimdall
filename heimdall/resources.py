"""API endpoints for the heimdall service."""

from flask import Blueprint, request
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
                return {'error': 'email has already been registered'}, HTTPStatus.CONFLICT

        except ValidationError as e:
            return e.messages, HTTPStatus.BAD_REQUEST
