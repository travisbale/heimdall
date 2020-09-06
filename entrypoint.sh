#!/bin/bash

if [ $1 = 'development' ]
then
    # Install requirements
    pip install --upgrade pip
    pip install -r requirements.txt
fi

# Apply database schema migrations
flask db upgrade

if [ $1 = 'development' ]
then
    # Run the service
    flask run -h 0.0.0.0
else
    gunicorn --bind 0.0.0.0:5000 'heimdall:create_app()'
fi
