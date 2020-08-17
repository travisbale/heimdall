#!/bin/bash

# Install requirements
pip install --upgrade pip
pip install -r requirements.txt

# Run the service
flask run -h 0.0.0.0
