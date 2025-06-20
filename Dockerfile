# Use Python slim image for smaller size and reduced attack surface
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=10000

# Create a non-root user
RUN useradd -m -r appuser && \
    mkdir -p /app/instance /app/userdata && \
    chown -R appuser:appuser /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    gcc \
    libsqlite3-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy requirements first to leverage Docker cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

RUN chmod 755 /app && \
    chmod -R 755 /app/instance && \
    chmod -R 755 /app/userdata && \
    chown -R appuser:appuser /app

USER appuser


EXPOSE 10000

# Run the application
CMD ["python", "app.py"] 