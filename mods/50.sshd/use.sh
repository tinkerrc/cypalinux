instconf $RC/sshd_config /etc/ssh/sshd_config
mkdir -p $BACKUP/sshd
mv /etc/ssh/sshd_config.d/*.conf $BACKUP/sshd

chown -R root:root /etc/ssh
chmod 755 /etc/ssh

chmod 644 /etc/ssh/*
systemctl restart sshd || perror "Could not restart sshd"
psuccess "Configured sshd"
