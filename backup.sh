#!/bin/bash
AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}
AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}
BUCKET_NAME=${AWS_BACKUP_BUCKET}

aws s3 cp /app/team_planner.db s3://${BUCKET_NAME}/backups/team_planner_$(date +\%Y\%m\%d\%H\%M\%S).db 