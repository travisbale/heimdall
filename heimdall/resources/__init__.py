from flask import Blueprint
from . import users, roles, role_assignments, permissions


bp = Blueprint('api', __name__)
users.register_resources(bp)
roles.register_resources(bp)
role_assignments.register_resources(bp)
permissions.register_resources(bp)
