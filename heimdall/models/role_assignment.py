from heimdall import db
from heimdall.models import BaseModel, BaseSchema
from marshmallow import fields


class RoleAssignment(BaseModel):
    __tablename__ = 'role_assignments'

    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), primary_key=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id', ondelete='CASCADE'), primary_key=True)

    def __init__(self, user_id, role_id):
        self.user_id = user_id
        self.role_id = role_id


class RoleAssignmentSchema(BaseSchema):
    roles = fields.List(fields.Integer, required=True)
