"""Permission module."""

from .base import BaseModel, BaseSchema
from heimdall import db
from marshmallow import fields, post_load


class Permission(BaseModel):
    """Represents a Permission object."""

    __tablename__ = 'permissions'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    description = db.Column(db.Text, default='', nullable=False)
    role_assignments = db.relationship('PermissionAssignment', backref='permission',
        cascade='all, delete-orphan')

    def __init__(self, name, description):
        self.name = name
        self.description = description

    @property
    def roles(self):
        """Return the roles currently assigned to the permission."""
        return [assignment.role for assignment in self.role_assignments]

    def __repr__(self):
        return f'<Permission {self.name}>'


class PermissionSchema(BaseSchema):
    """Serializes and deserializes permission objects."""

    id = fields.Integer()
    name = fields.String(required=True)
    description = fields.String(required=True)

    @post_load
    def load_permission(self, data, **kwargs):
        """Create a permission object using the deserialized values."""
        return Permission(**data)
