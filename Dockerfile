# Use Python 3.9 slim image
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Copy requirements first to leverage Docker cache
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Create instance and userdata directories with proper permissions
RUN mkdir -p instance userdata && \
    chmod 777 instance && \
    chmod 777 userdata

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PORT=10000
ENV FLASK_ENV=production

# Expose the port
EXPOSE ${PORT}

# Run the application with gunicorn
CMD gunicorn --bind 0.0.0.0:$PORT --workers 4 --threads 2 app:app 