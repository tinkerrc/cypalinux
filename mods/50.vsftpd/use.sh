#!/usr/bin/env bash
ufw allow ftp
ufw allow ftps
instconf $RC/vsftpd.conf /etc/vsftpd.conf
psuccess "Configured vsftpd"

if ! [[ -f /etc/ssl/private/vsftpd.key ]]; then
    mkdir -p /etc/ssl/private
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/vsftpd.key -out /etc/ssl/certs/vsftpd.crt -subj "/C=US/ST=California/L=Walnut/O=CyberPatriot/OU=High School Division/CN=FTP/emailAddress=test@example.com"
fi
chmod 700 /etc/ssl/{private,certs}
chmod 600 /etc/ssl/private/vsftpd.key
chmod 600 /etc/ssl/certs/vsftpd.crt
psuccess "Configured vsftpd TLS"

systemctl restart vsftpd && psuccess "Restarted vsftpd" || perror "Failed to restart vsftpd"
