"""Base classes module."""

from heimdall import db
from marshmallow import Schema

class BaseModel(db.Model):
    """
    Abstract base class for Flask models.

    This class provides a handful of methods to abstract the database session
    from the view layer.
    """

    # Mark the class as absctract to skip the production of a table
    __abstract__ = True

    def save(self):
        """
        Add the object to the session and write it to the transaction buffer.

        The transaction is committed when the calling request is completed.
        """
        db.session.add(self)
        db.session.flush()

    def merge(self):
        """
        Add the object to the session if it doesn't exist in the database.

        Try to reconcile the object with an instance in the session or the
        database based on the primary key. If the object does not exist create
        a new instance, add it to the session, then write the changes to the
        database transaction buffer. The transaction is committed when the
        calling request is completed.
        """
        db.session.merge(self)
        db.session.flush()

    def delete(self):
        """
        Mark the object for deletion.

        The transaction is committed when the calling request is completed.
        """
        db.session.delete(self)
        db.session.flush()


class BaseSchema(Schema):
    """Converts keys from snake to camel case during serialization."""

    def on_bind_field(self, field_name, field_obj):
        """Specify camel-cased output keys for each field in the schema."""
        words = iter((field_obj.data_key or field_name).split('_'))
        # Convert or set the data_key property for the field to camel-case
        field_obj.data_key = next(words) + ''.join(word.title() for word in words)
