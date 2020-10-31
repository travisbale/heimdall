from flask import jsonify, request
from flask_jwt_extended import jwt_required
from flask.views import MethodView
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
        if not request.is_json:
            return jsonify(msg='Request must be JSON'), HTTPStatus.BAD_REQUEST
        try:
            role = role_schema.load(request.get_json())

            if Role.query.filter_by(name=role.name).count() == 0:
                role.save()
                return jsonify(role_schema.dump(role)), HTTPStatus.CREATED
            else:
                return jsonify(msg='Role has already been created'), HTTPStatus.CONFLICT

        except ValidationError as e:
            return jsonify(e.messages), HTTPStatus.BAD_REQUEST


class RoleResource(MethodView):
    """Endpoint for roles."""

    @jwt_required
    def get(self, id):
        role = Role.query.get(id)

        if role is not None:
            return jsonify(role_schema.dump(role)), HTTPStatus.OK

        return jsonify(msg='Role does not exist'), HTTPStatus.NOT_FOUND

    @jwt_required
    def delete(self, id):
        role = Role.query.get(id)

        if role is not None:
            role.delete()
            return jsonify(msg='Role has been deleted'), HTTPStatus.OK

        return jsonify(msg='Role does not exist'), HTTPStatus.NOT_FOUND


def register_resources(bp):
    bp.add_url_rule('/roles', view_func=RolesResource.as_view('roles_resource'))
    bp.add_url_rule('/roles/<int:id>', view_func=RoleResource.as_view('role_resource'))
