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
    gunicorn -c gunicorn.py 'heimdall:create_app()'
fi
