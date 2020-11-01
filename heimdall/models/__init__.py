from heimdall import db
from marshmallow import Schema


class BaseModel(db.Model):
    """Abstract base class for Flask models."""

    __abstract__ = True

    def save(self):
        """Save the object to the database."""
        db.session.add(self)
        db.session.commit()

    def merge(self):
        db.session.merge(self)
        db.session.commit()

    def delete(self):
        """Delete the object from the database."""
        db.session.delete(self)
        db.session.commit()

class BaseSchema(Schema):
    """
    Schama that uses camel-case for external representation and snake-case for
    internal representation.
    """

    def on_bind_field(self, field_name, field_obj):
        """Specify camel-cased output keys by setting the data_key property"""
        words = iter((field_obj.data_key or field_name).split('_'))
        field_obj.data_key = next(words) + ''.join(word.title() for word in words)
