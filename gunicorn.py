# Gunicorn config file
# https://docs.gunicorn.org/en/stable/settings.html#config

bind = '0.0.0.0:5000'
workers = 2

errorlog = '-'
accesslog = '-'
