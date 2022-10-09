#!/usr/bin/env bash
instconf $RC/jail.local /etc/fail2ban/jail.local
systemctl restart fail2ban || service fail2ban restart || perror "Failed to restart fail2ban"
psuccess "Configured fail2ban"
