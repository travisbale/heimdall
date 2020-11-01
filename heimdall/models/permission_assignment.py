from heimdall import db
from heimdall.models import BaseModel, BaseSchema
from marshmallow import fields


class PermissionAssignment(BaseModel):
    __tablename__ = 'permission_assignments'

    role_id = db.Column(db.Integer, db.ForeignKey('roles.id', ondelete='CASCADE'), primary_key=True)
    permission_id = db.Column(db.Integer, db.ForeignKey('permissions.id', ondelete='CASCADE'), primary_key=True)

    def __init__(self, role_id, permission_id):
        self.role_id = role_id
        self.permission_id = permission_id


class PermissionAssignmentSchema(BaseSchema):
    permissions = fields.List(fields.Integer, required=True)
