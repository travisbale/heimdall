from flask import jsonify, request
from flask_jwt_extended import jwt_required
from flask.views import MethodView
from werkzeug.exceptions import Conflict
from heimdall.models.role import Role, RoleSchema
from marshmallow.exceptions import ValidationError
from http import HTTPStatus


role_schema = RoleSchema()


class RolesResource(MethodView):
    """Endpoint for roles."""

    @jwt_required
    def get(self):
        return jsonify(role_schema.dump(Role.query.all(), many=True)), HTTPStatus.OK

    @jwt_required
    def post(self):
        """Create a new role."""
        role = role_schema.load(request.get_json())

        if Role.query.filter_by(name=role.name).count() == 0:
            role.save()
            return jsonify(role_schema.dump(role)), HTTPStatus.CREATED
        else:
            raise Conflict(description='The role already exists')


class RoleResource(MethodView):
    """Endpoint for roles."""

    @jwt_required
    def get(self, id):
        role = Role.query.get_or_404(id, 'The role does not exist')
        return jsonify(role_schema.dump(role)), HTTPStatus.OK

    @jwt_required
    def delete(self, id):
        role = Role.query.get_or_404(id, 'The role does not exist')
        role.delete()
        return jsonify(message='The roles have been successfully deleted'), HTTPStatus.OK


def register_resources(bp):
    bp.add_url_rule('/roles', view_func=RolesResource.as_view('roles_resource'))
    bp.add_url_rule('/roles/<int:id>', view_func=RoleResource.as_view('role_resource'))
