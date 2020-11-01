"""Models for the heimdall service."""

from datetime import datetime
from flask_jwt_extended import create_access_token, create_refresh_token, get_jwt_identity
from heimdall import db
from heimdall.models import BaseModel, BaseSchema
from marshmallow import fields, post_load
from passlib.hash import argon2

class User(BaseModel):
    """User model for storing user related details."""

    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    _password = db.Column('password', db.String(255), nullable=False)
    registered_on = db.Column(db.DateTime, default=datetime.now(), nullable=False)
    roles = db.relationship('RoleAssignment', backref='user', cascade='all, delete-orphan')

    @classmethod
    def get_current_user(cls):
        return cls.query.filter_by(email=get_jwt_identity()).first()

    def __init__(self, email, password):
        """Create a new user given an email and a password."""
        self.email = email
        self.password = password
        self.registered_on = datetime.now()

    @property
    def password(self):
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
        return create_access_token(identity=self.email)

    def create_refresh_token(self):
        return create_refresh_token(identity=self.email)

    def is_current_user(self):
        return self.email == get_jwt_identity()

    def __repr__(self):
        """Return a human readable representation of the User."""
        return f'<User {self.email}>'


class UserSchema(BaseSchema):
    """Class used to serialize and deserialize User objects."""

    id = fields.Integer()
    email = fields.Email(required=True)
    password = fields.String(load_only=True, required=True)
    registered_on = fields.DateTime(dump_only=True)

    @post_load
    def load_user(self, data, **kwargs):
        """Create a user object from the serialized values."""
        return User(**data)
