#!/usr/bin/env bash
chmod 751 /lib/ufw
ufw --force reset

instconf $RC/ufw-sysctl.conf /etc/ufw/sysctl.conf
ufw enable

ufw logging high

ufw default deny incoming
ufw default allow outgoing

ufw allow ssh

ufw deny telnet
ufw deny 2049
ufw deny 515
ufw deny 111

psuccess "Configured UFW"

# See also: netsec
