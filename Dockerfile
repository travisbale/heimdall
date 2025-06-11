# Base images
FROM python:3.8-slim AS base

WORKDIR /app

# Set environment variables
ENV PYTYONDONTWRITEBYTECODE=1
ENV PYTHONBUFFERED=1
ENV FLASK_APP=heimdall

# Install dependencies
RUN pip install --upgrade pip
COPY ./requirements/production.txt /app/requirements.txt
RUN pip install -r requirements.txt

# Expose the webserver port
EXPOSE 5000


# Development image
FROM base AS development

ENV FLASK_ENV=development
RUN pip install debugpy
ENTRYPOINT [ "./entrypoint.sh", "development" ]


# Test image
FROM base AS test

ENV FLASK_ENV=development
RUN pip install pytest coverage
COPY . /app
CMD [ "python", "-m", "pytest" ]


# Production image
FROM base AS production

ENV FLASK_ENV=production
COPY . /app
ENTRYPOINT [ "./entrypoint.sh", "production" ]
