FROM python:3.12-slim AS builder

WORKDIR /app

# Install build dependencies for packages like lxml or cryptography
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libxml2-dev \
        libxslt-dev \
        libffi-dev \
        python3-dev \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies into /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

FROM python:3.12-slim

WORKDIR /app

# Copy installed Python packages from builder
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY . .

# Create volume for SQLite database
VOLUME ["/app/data"]
ENV DB_PATH=/app/data/linkwise.db

# Expose port
EXPOSE 8080

# Run the application with Gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "2", "--timeout", "120", "app:app"]
