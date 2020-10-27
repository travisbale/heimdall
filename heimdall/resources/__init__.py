from flask import Blueprint
from . import users


bp = Blueprint('api', __name__)
users.register_resources(bp)
