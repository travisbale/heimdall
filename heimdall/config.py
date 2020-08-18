"""Configuration settings for heimdall service."""

import os


class Config(object):
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    JWT_ALGORITHM='RS256'
    JWT_PRIVATE_KEY=open('keys/heimdall.pem').read()
    JWT_PUBLIC_KEY=open('keys/heimdall.pub').read()
    JWT_IDENTITY_CLAIM='sub'
    JWT_TOKEN_LOCATION='cookies'
    JWT_ACCESS_COOKIE_PATH='/api'
    JWT_ACCESS_CSRF_COOKIE_PATH='/'
    JWT_REFRESH_COOKIE_PATH='/api/refresh'
    JWT_REFRESH_CSRF_COOKIE_PATH='/'
    JWT_COOKIE_CSRF_PROTECT=True
    JWT_COOKIE_SECURE=False


class TestConfig(Config):
    TESTING = True
