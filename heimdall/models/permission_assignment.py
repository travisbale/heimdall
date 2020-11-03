"""Permission assignment module."""

from marshmallow import fields

from heimdall import db

from .base import BaseModel, BaseSchema


class PermissionAssignment(BaseModel):
    """Represents the association between roles and permissions."""

    __tablename__ = "permission_assignments"

    role_id = db.Column(db.Integer, db.ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True)
    permission_id = db.Column(db.Integer, db.ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True)

    def __init__(self, role_id, permission_id):
        self.role_id = role_id
        self.permission_id = permission_id


class PermissionAssignmentSchema(BaseSchema):
    """
    Deserializes a list of permission IDs.

    The permission IDs are then combined with a role ID and are used to create
    or delete PermissionAssignment objects. The role ID is retrieved from the
    route and does not require deserialization.
    """

    permission_ids = fields.List(fields.Integer, required=True)
