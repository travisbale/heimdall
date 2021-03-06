"""Role assignment module."""

from http import HTTPStatus

from flask import jsonify, request
from flask.views import MethodView
from werkzeug.exceptions import BadRequest

from heimdall.models.role import Role, RoleSchema
from heimdall.models.role_assignment import RoleAssignment, RoleAssignmentSchema
from heimdall.models.user import User

from .view_decorators import permissions_required

role_schema = RoleSchema()
assignment_schema = RoleAssignmentSchema()


class RoleAssignmentsResource(MethodView):
    """Dispatches request methods to view or modify the roles assigned to a user."""

    @permissions_required(["read:users", "read:roles"])
    def get(self, user_id):
        """Return all the roles that have been assigned to the user."""
        user = User.query.get_or_404(user_id, "The user does not exist")
        return jsonify(role_schema.dump(user.roles, many=True)), HTTPStatus.OK

    @permissions_required(["update:users", "read:roles"])
    def post(self, user_id):
        """Assign the roles to the user."""
        roles = self._get_roles(user_id)

        for role in roles:
            assignment = RoleAssignment(user_id, role.id)
            assignment.merge()

        return jsonify(message="The roles were assigned to the user"), HTTPStatus.CREATED

    @permissions_required(["update:users", "read:roles"])
    def delete(self, user_id):
        """Unassign the roles from the user."""
        roles = self._get_roles(user_id)
        assignments = RoleAssignment.query.filter(
            RoleAssignment.role_id.in_(map(lambda role: role.id, roles)),
            RoleAssignment.user_id == user_id,
        )

        for assignment in assignments:
            assignment.delete()

        return jsonify(message="The roles were unassigned from the user"), HTTPStatus.OK

    def _get_roles(self, user_id):
        """Retrieve the roles based on the role IDs in the request."""
        # Verify that the user exists
        User.query.get_or_404(user_id, "The user does not exist")

        # Get the list of roles from the database
        request_json = assignment_schema.load(request.get_json())
        roles = Role.query.filter(Role.id.in_(request_json["role_ids"]))

        # Check that all the roles exist
        if roles.count() != len(request_json["role_ids"]):
            raise BadRequest(description="One or more of the roles do not exist")

        return roles


def register_resources(bp):
    """Add the resource routes to the application blueprint."""
    bp.add_url_rule(
        "/users/<int:user_id>/roles",
        view_func=RoleAssignmentsResource.as_view("role_assignments_resource"),
    )
