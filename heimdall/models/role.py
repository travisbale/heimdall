"""Role module."""

from heimdall import db
from .base import BaseModel, BaseSchema
from marshmallow import fields, post_load


class Role(BaseModel):
    """Represents a Role object."""

    __tablename__ = 'roles'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(32), nullable=False, unique=True)
    description = db.Column(db.Text, default='', nullable=False)
    user_assignments = db.relationship('RoleAssignment', backref='role', cascade='all, delete-orphan')
    permission_assignments = db.relationship('PermissionAssignment', backref='role', cascade='all, delete-orphan')

    def __init__(self, name, description):
        self.name = name
        self.description = description

    @property
    def users(self):
        """Return the users currently assigned to the role."""
        return [assignment.user for assignment in self.user_assignments]

    @property
    def permissions(self):
        """Return the permissions currently assigned to the role."""
        return [assignment.permission for assignment in self.permission_assignments]

    def __repr__(self):
        return f'<Role {self.name}>'


class RoleSchema(BaseSchema):
    """Serializes and deserializes role objects."""

    id = fields.Integer()
    name = fields.String(required=True)
    description = fields.String(required=True)

    @post_load
    def load_role(self, data, **kwargs):
        """Create a role object using the deserialized values."""
        return Role(**data)
