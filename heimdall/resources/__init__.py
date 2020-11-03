"""Resources package."""

from flask import Blueprint

from . import permission_assignments, permissions, role_assignments, roles, users

# Create a blueprint for the application resources
bp = Blueprint('api', __name__)

# Register the resources from each module
users.register_resources(bp)
roles.register_resources(bp)
role_assignments.register_resources(bp)
permissions.register_resources(bp)
permission_assignments.register_resources(bp)
