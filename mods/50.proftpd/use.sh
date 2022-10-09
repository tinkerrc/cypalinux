#!/usr/bin/env bash
# TODO: http://www.proftpd.org/docs/howto/TLS.html
ufw allow ftp
ufw allow ftps

mkdir -p /var/log/proftpd/
touch /var/log/proftpd/tls.log
chown proftpd:root /var/log/proftpd/tls.log
psuccess "Created log file"

instconf $RC/proftpd.conf /etc/proftpd/proftpd.conf
mkdir -p $BACKUP/proftpd
mv /etc/proftpd/conf.d/* $BACKUP/proftpd
psuccess "Configured proftpd"

instconf $RC/tls.conf /etc/proftpd/tls.conf
if ! [[ -f /etc/ssl/private/proftpd.key ]]; then
    mkdir -p /etc/ssl/private
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/proftpd.key -out /etc/ssl/certs/proftpd.crt -subj "/C=US/ST=California/L=Walnut/O=CyberPatriot/OU=High School Division/CN=FTP/emailAddress=test@example.com"
fi
chmod 700 /etc/ssl/{private,certs}
chmod 600 /etc/ssl/private/proftpd.key
chmod 600 /etc/ssl/certs/proftpd.crt
psuccess "Configured proftpd TLS"

systemctl restart proftpd && psuccess "Restarted proftpd" || perror "Failed to restart proftpd"
