#!/usr/bin/env bash
cp -ar /var/spool/cron/ "$BACKUP/quarantine"
rm /var/spool/cron/crontabs/*
psuccess "Removed all user crontabs"

# only root can use cron & at
echo "root" > /etc/cron.allow
echo "root" > /etc/at.allow
chmod 644 /etc/{cron,at}.allow
psuccess "Restricted cron access"

systemctl restart cron && psuccess "Restarted cron daemon" || perror "Failed to restart cron daemon"

ptodo "Inspect original crontabs"
ptodo "Inspect /var/spool/anacron /etc/crontab /etc/anacrontab /etc/cron.* etc"

psuccess "Configured cron"
