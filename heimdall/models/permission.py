from . import BaseModel
from heimdall import db
from marshmallow import fields, post_load, Schema


class Permission(BaseModel):
    __tablename__ = 'permissions'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    description = db.Column(db.Text, default='', nullable=False)

    def __init__(self, name, description):
        self.name = name
        self.description = description

    def __repr__(self):
        return f'<Permission {self.name}>'


class PermissionSchema(Schema):
    id = fields.Integer()
    name = fields.String(required=True)
    description = fields.String(required=True)

    @post_load
    def load_permission(self, data, **kwargs):
        return Permission(**data)
