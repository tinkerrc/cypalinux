#!/usr/bin/env bash
instconf $RC/sshd_config /etc/ssh/sshd_config
mkdir -p $BACKUP/sshd
mv /etc/ssh/sshd_config.d/*.conf $BACKUP/sshd

chown -R root:root /etc/ssh
chmod 755 /etc/ssh

chmod 644 /etc/ssh/*
systemctl restart sshd || perror "Could not restart sshd"
psuccess "Configured sshd"

if [[ -f /etc/ssh/moduli ]]; then
    pinfo "Removing short moduli"
    backup /etc/ssh/moduli
    sudo awk '$5 >= 3071' /etc/ssh/moduli | sudo tee /etc/ssh/moduli.tmp
    sudo mv /etc/ssh/moduli.tmp /etc/ssh/moduli
fi
