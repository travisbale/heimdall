"""User module."""

from datetime import datetime
from flask_jwt_extended import create_access_token, create_refresh_token, get_jwt_identity
from heimdall import db
from heimdall.models import BaseModel, BaseSchema
from marshmallow import fields, post_load
from passlib.hash import argon2

class User(BaseModel):
    """Represents a User object."""

    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    _password = db.Column('password', db.String(255), nullable=False)
    registered_on = db.Column(db.DateTime, default=datetime.now(), nullable=False)
    roles = db.relationship('RoleAssignment', backref='user', cascade='all, delete-orphan')

    @classmethod
    def get_current_user(cls):
        """Return the currently logged in user using the JWT identity."""
        return cls.query.filter_by(email=get_jwt_identity()).first()

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

    def authenticate(self, password):
        """Check the provided password against the user's saved password."""
        try:
            return argon2.verify(password, self.password)
        except (TypeError, ValueError):
            return False

    def create_access_token(self):
        """Create and return a new JWT access token."""
        return create_access_token(identity=self.email)

    def create_refresh_token(self):
        """Create and return a new JWT refresh token."""
        return create_refresh_token(identity=self.email)

    def is_current_user(self):
        """Return whether or not the user is currently logged in."""
        return self.email == get_jwt_identity()

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

    @post_load
    def load_user(self, data, **kwargs):
        """Create a user object using the deserialized values."""
        return User(**data)
