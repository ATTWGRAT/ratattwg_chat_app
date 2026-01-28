#!/bin/bash
# Database backup script
# Add to crontab for automated backups: 0 2 * * * /path/to/backup.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BACKUP_DIR="$PROJECT_DIR/backups"
DATE=$(date +%Y%m%d_%H%M%S)
CONTAINER_NAME="secure-chat-app"

# Create backup directory
mkdir -p "$BACKUP_DIR"

echo "Starting backup at $(date)"

# Check if container is running
if ! docker ps | grep -q "$CONTAINER_NAME"; then
    echo "Error: Container $CONTAINER_NAME is not running"
    exit 1
fi

# Backup database
echo "Backing up database..."
docker exec "$CONTAINER_NAME" cat /app/backend/instance/app.db > "$BACKUP_DIR/db_$DATE.db"

if [ $? -eq 0 ]; then
    echo "Database backup created: $BACKUP_DIR/db_$DATE.db"
    
    # Compress backup
    gzip "$BACKUP_DIR/db_$DATE.db"
    echo "Backup compressed: $BACKUP_DIR/db_$DATE.db.gz"
    
    # Keep only last 7 days of backups
    echo "Cleaning old backups..."
    find "$BACKUP_DIR" -name "db_*.db.gz" -mtime +7 -delete
    
    # Calculate backup size
    BACKUP_SIZE=$(du -h "$BACKUP_DIR/db_$DATE.db.gz" | cut -f1)
    echo "Backup size: $BACKUP_SIZE"
else
    echo "Error: Failed to create backup"
    exit 1
fi

echo "Backup completed successfully at $(date)"

# Optional: Send notification (uncomment and configure)
# curl -X POST https://your-monitoring-service.com/webhook \
#     -H 'Content-Type: application/json' \
#     -d "{\"message\": \"Database backup completed: $DATE\", \"size\": \"$BACKUP_SIZE\"}"
