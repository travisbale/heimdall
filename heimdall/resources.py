"""API endpoints for the heimdall service."""

from flask import Blueprint, jsonify, request
from flask.views import MethodView
from flask_jwt_extended.utils import get_jwt_identity
from flask_jwt_extended.view_decorators import jwt_required
from marshmallow.exceptions import ValidationError
from heimdall.models import User, UserSchema
from http import HTTPStatus


bp = Blueprint('api', __name__)
user_schema = UserSchema()

class UsersResource(MethodView):
    """Application endpoint for User objects."""

    def post(self):
        """Create a new user account."""
        try:
            user = user_schema.load(request.get_json())

            if User.query.filter_by(email=user.email).count() == 0:
                user.save()
                return jsonify(user_schema.dump(user)), HTTPStatus.CREATED
            else:
                return jsonify({'msg': 'Email has already been registered'}), HTTPStatus.CONFLICT

        except ValidationError as e:
            return jsonify(e.messages), HTTPStatus.BAD_REQUEST


class UserResource(MethodView):
    """Application endpoint for user objects."""

    @jwt_required
    def delete(self, id):
        user = User.query.get(id)

        if user is not None and user.email == get_jwt_identity():
            user.delete()
            return jsonify({'msg': 'User has been deleted'}), HTTPStatus.OK

        return jsonify({'msg': 'Cannot delete user'}), HTTPStatus.FORBIDDEN


bp.add_url_rule('/users', view_func=UsersResource.as_view('users_resource'))
bp.add_url_rule('/users/<int:id>', view_func=UserResource.as_view('user_resource'))
