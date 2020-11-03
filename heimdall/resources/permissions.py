"""Permissions module."""

from heimdall.resources.view_decorators import permission_required
from flask.views import MethodView
from heimdall.models.permission import Permission, PermissionSchema
from http import HTTPStatus
from flask import jsonify, request
from werkzeug.exceptions import Conflict


# Schema for permission serialization/deserialization
schema = PermissionSchema()


class PermissionsResource(MethodView):
    """Dispatches request methods to retrieve or create permissions."""

    @permission_required('read:permissions')
    def get(self):
        """Return a list of all the permissions."""
        return jsonify(schema.dump(Permission.query.all(), many=True)), HTTPStatus.OK

    @permission_required('create:permissions')
    def post(self):
        """Create a new permission."""
        perm = schema.load(request.get_json())

        if Permission.query.filter_by(name=perm.name).count() > 0:
            raise Conflict(description='The permission already exists')

        perm.save()
        return jsonify(schema.dump(perm)), HTTPStatus.CREATED


class PermissionResource(MethodView):
    """Dispatches request methods to retrieve or delete an existing permission."""

    @permission_required('read:permissions')
    def get(self, id):
        """Return the permission with the given ID."""
        perm = Permission.query.get_or_404(id, 'The permission does not exist')
        return jsonify(schema.dump(perm)), HTTPStatus.OK

    @permission_required('delete:permissions')
    def delete(self, id):
        """Delete the permission with the given ID."""
        perm = Permission.query.get_or_404(id, 'The permission does not exist')
        perm.delete()
        return jsonify(message='The permission has been deleted'), HTTPStatus.OK


def register_resources(bp):
    """Add the resource routes to the application blueprint."""
    bp.add_url_rule('/permissions', view_func=PermissionsResource.as_view('permissions_resource'))
    bp.add_url_rule('/permissions/<int:id>', view_func=PermissionResource.as_view('permission_resource'))
