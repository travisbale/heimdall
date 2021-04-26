#!/bin/bash

# Apply database schema migrations
flask db upgrade

# Run the service
if [ $1 = 'development' ]
then
    python -m debugpy --listen 0.0.0.0:6789 -m flask run -h 0.0.0.0
else
    gunicorn -c gunicorn.py 'heimdall:create_app()'
fi
