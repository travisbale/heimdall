"""
View decorators module.

This module contains functions and decorators that extend the functionality of
the decorators provided by flask_jwt_extended.
"""

from functools import wraps

from flask_jwt_extended.utils import get_jwt_claims
from flask_jwt_extended.view_decorators import verify_jwt_in_request
from werkzeug.exceptions import Forbidden


def permission_required(permission):
    """
    Protect a Flask endpoint from unauthorized access.

    This decorator will ensure that the requester has a valid access token, as
    well as a claim for the permission argument before allowing the endpoint to
    be called. If the requester is denied access a Forbidden exception is
    raised.
    """
    return permissions_required([permission])


def permissions_required(permissions):
    """
    Protect a Flask endpoint from unauthorized access.

    This decorator will ensure the requester has a valid access token, as well
    as claims for all the permissions in the argument list before allowing the
    endpoint to be called. If the requester is denied access a Forbidden
    exception is raised.
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            verify_permissions_in_claims(permissions)
            return fn(*args, **kwargs)

        return wrapper
    return decorator


def verify_permissions_in_claims(required_permissions):
    """
    Ensure that the requester has been granted the permissions.

    Raises a Forbidden exception if the requester does not have sufficient
    permissions to proceed.
    """
    verify_jwt_in_request()
    claims = get_jwt_claims()

    # Check that the permission claims contain all the required permissions
    if not all(perm in claims['permissions'] for perm in required_permissions):
        raise Forbidden(description='Insufficient permissions')
