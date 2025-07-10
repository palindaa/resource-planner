#!/bin/bash
AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}
AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}
BUCKET_NAME=${AWS_BACKUP_BUCKET}

# Get the latest backup file
latest_backup=$(aws s3 ls s3://${BUCKET_NAME}/backups/ | grep 'team_planner_' | sort -r | head -n 1 | awk '{print $4}')

# Download the latest backup to current directory
aws s3 cp s3://${BUCKET_NAME}/backups/$latest_backup /app/