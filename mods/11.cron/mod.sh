# TODO: add checklist item: check all cron files
cp -r /var/spool/cron/ "$BACKUP/quarantine"
rm /var/spool/cron/crontabs/*
psuccess "Removed all user crontabs"

# only root can use cron & at
echo "root" > /etc/cron.allow
echo "root" > /etc/at.allow
chmod 644 /etc/{cron,at}.allow
psuccess "Restrict cron access"

pinfo "Restarting cron... "
systemctl restart cron
psuccess "Restarting cron... Done"
