"""Roles module."""

from flask import jsonify, request
from flask_jwt_extended import jwt_required
from flask.views import MethodView
from werkzeug.exceptions import Conflict
from heimdall.models.role import Role, RoleSchema
from http import HTTPStatus


# Schema for role serialization and deserialization
role_schema = RoleSchema()


class RolesResource(MethodView):
    """Dispatches request methods to retrieve or create roles."""

    @jwt_required
    def get(self):
        """Return a list of all the roles."""
        return jsonify(role_schema.dump(Role.query.all(), many=True)), HTTPStatus.OK

    @jwt_required
    def post(self):
        """Create a new role."""
        role = role_schema.load(request.get_json())

        if Role.query.filter_by(name=role.name).count() > 0:
            raise Conflict(description='The role already exists')

        role.save()
        return jsonify(role_schema.dump(role)), HTTPStatus.CREATED


class RoleResource(MethodView):
    """Dispatches request methods to retrieve or delete an existing role."""

    @jwt_required
    def get(self, id):
        """Return the role with the given ID."""
        role = Role.query.get_or_404(id, 'The role does not exist')
        return jsonify(role_schema.dump(role)), HTTPStatus.OK

    @jwt_required
    def delete(self, id):
        """Delete the role with the given ID."""
        role = Role.query.get_or_404(id, 'The role does not exist')
        role.delete()
        return jsonify(message='The role has been deleted'), HTTPStatus.OK


def register_resources(bp):
    """Add the resource routes to the application blueprint."""
    bp.add_url_rule('/roles', view_func=RolesResource.as_view('roles_resource'))
    bp.add_url_rule('/roles/<int:id>', view_func=RoleResource.as_view('role_resource'))
