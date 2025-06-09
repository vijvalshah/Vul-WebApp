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

# Create instance and userdata directories
RUN mkdir -p instance userdata

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PORT=10000

# Expose the port
EXPOSE ${PORT}

# Run the application with gunicorn
CMD gunicorn --bind 0.0.0.0:$PORT app:app 