"""
Flask module.

This module is used to subclass some of the default Flask classes in order to
modify the way json is parsed.
"""

from flask import Flask as _Flask
from flask import Request as _Request
from werkzeug.exceptions import UnsupportedMediaType


class Request(_Request):
    """Subclasses the Flask Request class to override get_json()."""

    def get_json(self, **kwargs):
        """
        Raise an exception if the MIME type does not indicate JSON.

        This removes the requirement to check the MIME type for JSON on every
        request before trying to parse it. If the request is not JSON the thrown
        exception will be caught and handled by the flask error handler.
        """
        if not self.is_json:
            raise UnsupportedMediaType('The request must be JSON')

        # If the request is JSON return the result of the parent method
        return super(Request, self).get_json(**kwargs)


class Flask(_Flask):
    """Subclasses the Flask class and overrides the default request class."""

    request_class = Request
