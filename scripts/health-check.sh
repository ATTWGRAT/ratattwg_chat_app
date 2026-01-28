#!/bin/bash
# Health check script for monitoring
# Can be used with monitoring services or cron jobs

CONTAINER_NAME="secure-chat-app"
HEALTH_ENDPOINT="https://localhost/health"
LOG_FILE="/var/log/app-health-check.log"
ALERT_EMAIL="admin@example.com"  # Configure if needed

# Function to log messages
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Function to send alert (configure with your alerting system)
send_alert() {
    local message="$1"
    log_message "ALERT: $message"
    
    # Uncomment and configure your preferred alerting method:
    
    # Email alert
    # echo "$message" | mail -s "App Health Check Alert" "$ALERT_EMAIL"
    
    # Slack webhook
    # curl -X POST -H 'Content-type: application/json' \
    #   --data "{\"text\":\"$message\"}" \
    #   YOUR_SLACK_WEBHOOK_URL
    
    # Discord webhook
    # curl -X POST -H 'Content-Type: application/json' \
    #   -d "{\"content\":\"$message\"}" \
    #   YOUR_DISCORD_WEBHOOK_URL
}

# Check if container is running
if ! docker ps | grep -q "$CONTAINER_NAME"; then
    send_alert "Container $CONTAINER_NAME is not running!"
    exit 1
fi

# Check container health status
container_health=$(docker inspect --format='{{.State.Health.Status}}' "$CONTAINER_NAME" 2>/dev/null)
if [ "$container_health" = "unhealthy" ]; then
    send_alert "Container $CONTAINER_NAME is unhealthy!"
    exit 1
fi

# Check HTTP health endpoint
http_code=$(curl -k -s -o /dev/null -w "%{http_code}" "$HEALTH_ENDPOINT" --max-time 10)
if [ "$http_code" != "200" ]; then
    send_alert "Health endpoint returned HTTP $http_code (expected 200)"
    exit 1
fi

# Check response content
response=$(curl -k -s "$HEALTH_ENDPOINT" --max-time 10)
if ! echo "$response" | grep -q "healthy"; then
    send_alert "Health endpoint response invalid: $response"
    exit 1
fi

# Check container resource usage
cpu_usage=$(docker stats --no-stream --format "{{.CPUPerc}}" "$CONTAINER_NAME" | sed 's/%//')
mem_usage=$(docker stats --no-stream --format "{{.MemPerc}}" "$CONTAINER_NAME" | sed 's/%//')

# Alert if CPU > 90%
if (( $(echo "$cpu_usage > 90" | bc -l) )); then
    send_alert "High CPU usage: ${cpu_usage}%"
fi

# Alert if Memory > 90%
if (( $(echo "$mem_usage > 90" | bc -l) )); then
    send_alert "High memory usage: ${mem_usage}%"
fi

log_message "Health check passed - CPU: ${cpu_usage}%, Memory: ${mem_usage}%"
exit 0
