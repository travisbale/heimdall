FROM python:3.8-slim

WORKDIR /app

# Set environment variables
ENV PYTYONDONTWRITEBYTECODE 1
ENV PYTHONBUFFERED 1

# Install dependencies
RUN pip install --upgrade pip
COPY ./requirements/production.txt /app/requirements.txt
RUN pip install -r requirements.txt

# Expose the port gunicorn runs on
EXPOSE 5000

# Copy project
COPY . /app

# Start the container
CMD [ "./entrypoint.sh", "production" ]
