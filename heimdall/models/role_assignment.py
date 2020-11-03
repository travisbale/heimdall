"""Role assignment module."""

from marshmallow import fields

from heimdall import db

from .base import BaseModel, BaseSchema


class RoleAssignment(BaseModel):
    """Represents the association between users and roles."""

    __tablename__ = 'role_assignments'

    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), primary_key=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id', ondelete='CASCADE'), primary_key=True)

    def __init__(self, user_id, role_id):
        self.user_id = user_id
        self.role_id = role_id


class RoleAssignmentSchema(BaseSchema):
    """
    Deserializes a list of role IDs.

    The role IDs are then combined with a user ID and are used to create or
    delete RoleAssignment objects. The user ID is retrieved from the route and
    does not require deserialization.
    """

    role_ids = fields.List(fields.Integer, required=True)
