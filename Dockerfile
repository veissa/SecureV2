FROM python:3.8-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    libmagic1 \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first to leverage Docker cache
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install python-magic

# Create non-root user
RUN useradd -m appuser

# Copy application code
COPY . .

# Create necessary directories and set permissions
RUN mkdir -p uploads keys \
    && chown -R appuser:appuser /app \
    && chmod -R 755 /app

# Set environment variables
ENV FLASK_APP=app.py
ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 5000

# Run the application
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"] 