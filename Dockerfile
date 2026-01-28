# Multi-stage build for production deployment
# Stage 1: Build Frontend
FROM node:18-alpine AS frontend-builder

WORKDIR /frontend
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ ./
RUN npm run build

# Stage 2: Setup Backend and Nginx
FROM python:3.13-slim

# Install nginx and required packages
RUN apt-get update && apt-get install -y \
    nginx \
    supervisor \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create application directory
WORKDIR /app

# Copy backend requirements and install dependencies
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn eventlet

# Copy backend application
COPY backend/ ./backend/

# Copy built frontend from previous stage
COPY --from=frontend-builder /frontend/dist /var/www/html

# Copy nginx configuration
COPY docker/nginx.conf /etc/nginx/nginx.conf
COPY docker/app.conf /etc/nginx/sites-available/app.conf
RUN ln -sf /etc/nginx/sites-available/app.conf /etc/nginx/sites-enabled/app.conf \
    && rm -f /etc/nginx/sites-enabled/default

# Copy supervisor configuration
COPY docker/supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Create SSL certificates directory (certificates will be mounted at runtime)
RUN mkdir -p /etc/nginx/ssl

# Create necessary directories with proper permissions
RUN mkdir -p /app/backend/instance /app/backend/logs /var/log/nginx \
    && chmod -R 777 /app/backend/instance /app/backend/logs /var/log/nginx

# Expose ports
EXPOSE 80 443

# Start supervisor to manage nginx and gunicorn
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
