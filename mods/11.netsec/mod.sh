#!/usr/bin/env bash
instconf $RC/interfaces /etc/network/interfaces
instconf $RC/nsswitch.conf /etc/nsswitch.conf
instconf $RC/host.conf /etc/host.conf
instconf $RC/hosts /etc/hosts
echo "127.0.0.1 localhost $(hostname)" >> /etc/hosts
instconf $RC/resolved.conf /etc/systemd/resolved.conf

rm -rf /etc/systemd/resolved.conf.d
psuccess "Networking configurations installed"

systemctl restart systemd-resolved && psuccess "systemd-resolved restarted" || perror "Failed to restart systemd-resolved"

rm -f /home/*/.{netrc,forward,rhosts}
psuccess "Removed rsh artifacts"
# See also: ufw
