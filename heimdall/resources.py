"""API endpoints for the heimdall service."""

from flask import Blueprint
from flask_restful import Api, Resource
from http import HTTPStatus


bp = Blueprint('api', __name__)
api = Api(bp)


@api.resource('/users')
class UsersResource(Resource):
    """Application endpoint for User objects."""

    def get(self):
        return {'hello': 'world'}, HTTPStatus.OK
