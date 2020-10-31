from flask import Blueprint
from . import users, roles


bp = Blueprint('api', __name__)
users.register_resources(bp)
roles.register_resources(bp)
