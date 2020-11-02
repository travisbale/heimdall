"""Permission assignments module."""

from flask import jsonify, request
from flask_jwt_extended import jwt_required
from flask.views import MethodView
from heimdall.models.permission import Permission, PermissionSchema
from heimdall.models.permission_assignment import PermissionAssignment, PermissionAssignmentSchema
from heimdall.models.role import Role
from http import HTTPStatus
from werkzeug.exceptions import BadRequest


# Schemas for permission serialization and deserialization
permission_schema = PermissionSchema()
assignment_schema = PermissionAssignmentSchema()


class PermissionAssignmentsResource(MethodView):
    """Dispatches request methods to view or modify the permissions assigned to a role."""

    @jwt_required
    def get(self, role_id):
        """Return all the permissions that have been assigned to the role."""
        permissions = Permission.query.join(Permission.roles).filter_by(role_id=role_id)
        return jsonify(permission_schema.dump(permissions, many=True)), HTTPStatus.OK

    @jwt_required
    def post(self, role_id):
        """Assign the permissions to the role."""
        permissions = self._get_permissions(role_id)

        for permission in permissions:
            assignment = PermissionAssignment(role_id, permission.id)
            assignment.merge()

        return jsonify(message='The permissions were assigned to the role'), HTTPStatus.CREATED

    @jwt_required
    def delete(self, role_id):
        """Unassign the permissions from the role."""
        permissions = self._get_permissions(role_id)
        assignments = PermissionAssignment.query.filter(
            PermissionAssignment.permission_id.in_(map(lambda perm: perm.id, permissions)),
            PermissionAssignment.role_id == role_id)

        for assignment in assignments:
            assignment.delete()

        return jsonify(message='The permissions were unassigned from the user'), HTTPStatus.OK

    def _get_permissions(self, role_id):
        """Retreive the permissions based on the permission IDs in the request."""
        # Verify that the role being assigned the permissions exists
        Role.query.get_or_404(role_id, 'The role does not exist')

        # Get the list of permissions to be assigned from the database
        request_json = assignment_schema.load(request.get_json())
        permissions = Permission.query.filter(Permission.id.in_(request_json['permission_ids']))

        # Check that all the permissions exist
        if permissions.count() != len(request_json['permission_ids']):
            raise BadRequest(description='One or more of the permissions do not exist')

        return permissions


def register_resources(bp):
    """Add the resource routes to the application blueprint."""
    bp.add_url_rule('/roles/<int:role_id>/permissions',
        view_func=PermissionAssignmentsResource.as_view('permission_assignments_resource'))
