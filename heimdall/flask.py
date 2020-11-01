from flask import Flask as _Flask, Request as _Request
from werkzeug.exceptions import UnsupportedMediaType


class Request(_Request):
    """
    Subclass the Flask Request class in order to override the get_json()
    function.
    """

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
    """
    Subclass the Flask class so the default request class can be overridden.
    """
    request_class = Request
