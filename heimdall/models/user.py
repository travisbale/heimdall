"""User module."""

from datetime import datetime

from marshmallow import fields, post_load
from passlib.hash import argon2

from heimdall import db

from .base import BaseModel, BaseSchema


class User(BaseModel):
    """Represents a User object."""

    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    _password = db.Column('password', db.String(255), nullable=False)
    registered_on = db.Column(db.DateTime, default=datetime.now(), nullable=False)
    role_assignments = db.relationship('RoleAssignment', backref='user', cascade='all, delete-orphan')

    def __init__(self, email, password):
        self.email = email
        self.password = password
        self.registered_on = datetime.now()

    @property
    def password(self):
        """Return the hashed password."""
        return self._password

    @password.setter
    def password(self, password):
        self._password = argon2.hash(password)

    @property
    def roles(self):
        """Return the list of roles currently assigned to the user."""
        return [assignment.role for assignment in self.role_assignments]

    @property
    def permissions(self):
        """Return the list of permissions currently assigned to the user."""
        permissions = [permission for role in self.roles for permission in role.permissions]
        # Remove any duplicates as multiple roles could have the same permissions
        return list(dict.fromkeys(permissions))

    def authenticate(self, password):
        """Check the provided password against the user's saved password."""
        try:
            return argon2.verify(password, self.password)
        except (TypeError, ValueError):
            return False

    def __repr__(self):
        """Return a human readable representation of the User."""
        return f'<User {self.email}>'


class LoginSchema(BaseSchema):
    """Deserializes and validates user login information."""

    email = fields.Email(required=True)
    password = fields.String(load_only=True, required=True)


class UserSchema(LoginSchema):
    """Serializes and deserializes User objects."""

    id = fields.Integer()
    registered_on = fields.DateTime(dump_only=True)
    roles = fields.Pluck('RoleSchema', 'name', many=True)
    permissions = fields.Pluck('PermissionSchema', 'name', many=True)

    @post_load
    def load_user(self, data, **kwargs):
        """Create a user object using the deserialized values."""
        return User(**data)
