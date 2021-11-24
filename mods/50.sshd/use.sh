instconf $RC/sshd_config /etc/ssh/sshd_config
mkdir -p $BACKUP/sshd
mv /etc/ssh/sshd_config.d/*.conf $BACKUP/sshd
systemctl restart sshd || perror "Could not restart sshd"
psuccess "Configured sshd"
