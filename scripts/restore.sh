#!/bin/bash
# Restore database from backup
# Usage: ./restore.sh backup-file.db.gz

if [ -z "$1" ]; then
    echo "Usage: ./restore.sh <backup-file.db.gz>"
    echo ""
    echo "Available backups:"
    ls -lh ../backups/db_*.db.gz 2>/dev/null || echo "No backups found"
    exit 1
fi

BACKUP_FILE="$1"
CONTAINER_NAME="secure-chat-app"

if [ ! -f "$BACKUP_FILE" ]; then
    echo "Error: Backup file not found: $BACKUP_FILE"
    exit 1
fi

echo "WARNING: This will replace the current database!"
echo "Backup file: $BACKUP_FILE"
read -p "Are you sure you want to continue? (yes/no): " confirm

if [ "$confirm" != "yes" ]; then
    echo "Restore cancelled"
    exit 0
fi

# Check if container is running
if ! docker ps | grep -q "$CONTAINER_NAME"; then
    echo "Error: Container $CONTAINER_NAME is not running"
    exit 1
fi

# Create temporary directory
TMP_DIR=$(mktemp -d)
TMP_DB="$TMP_DIR/app.db"

# Decompress backup
echo "Decompressing backup..."
if [[ "$BACKUP_FILE" == *.gz ]]; then
    gunzip -c "$BACKUP_FILE" > "$TMP_DB"
else
    cp "$BACKUP_FILE" "$TMP_DB"
fi

if [ ! -f "$TMP_DB" ]; then
    echo "Error: Failed to decompress backup"
    rm -rf "$TMP_DIR"
    exit 1
fi

# Stop application (optional, for data consistency)
echo "Stopping application..."
docker-compose -f "$(dirname "$0")/../docker-compose.yml" stop app

# Restore database
echo "Restoring database..."
cat "$TMP_DB" | docker exec -i "$CONTAINER_NAME" tee /app/backend/instance/app.db > /dev/null

if [ $? -eq 0 ]; then
    echo "Database restored successfully"
else
    echo "Error: Failed to restore database"
    rm -rf "$TMP_DIR"
    exit 1
fi

# Start application
echo "Starting application..."
docker-compose -f "$(dirname "$0")/../docker-compose.yml" start app

# Cleanup
rm -rf "$TMP_DIR"

echo "Restore completed successfully"
