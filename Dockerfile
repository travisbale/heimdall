FROM python:3.8-slim

WORKDIR /app

# Set environment variables
ENV PYTYONDONTWRITEBYTECODE 1
ENV PYTHONBUFFERED 1

# Install dependencies
RUN pip install --upgrade pip
RUN pip install pip-tools
COPY ./requirements/production.txt /app/requirements.txt
RUN pip-sync

# Expose the port gunicorn runs on
EXPOSE 5000

# Copy project
COPY . /app

# Start the container
CMD [ "./entrypoint.sh", "production" ]
