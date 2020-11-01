from heimdall import db
from heimdall.models import BaseModel, BaseSchema
from marshmallow import fields, post_load


class Role(BaseModel):
    __tablename__ = 'roles'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(32), nullable=False, unique=True)
    description = db.Column(db.Text, default='', nullable=False)
    users = db.relationship('RoleAssignment', backref='role', cascade='all, delete-orphan')
    permissions = db.relationship('PermissionAssignment', backref='role', cascade='all, delete-orphan')

    def __init__(self, name, description):
        self.name = name
        self.description = description

    def __repr__(self):
        return f'<Role {self.name}>'


class RoleSchema(BaseSchema):
    id = fields.Integer()
    name = fields.String(required=True)
    description = fields.String(required=True)

    @post_load
    def load_role(self, data, **kwargs):
        return Role(**data)
