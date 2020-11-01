from heimdall import db


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
