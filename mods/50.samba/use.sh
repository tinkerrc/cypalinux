#!/usr/bin/env bash
sed -i 's/^.*guest ok.*$/    guest ok = no/' /etc/samba/smb.conf
sed -i 's/^.*usershare allow guests.*$/usershare allow guests = no/' /etc/samba/smb.conf
if use apparmor; then
    instconf $RC/usr.sbin.smbd /etc/apparmor.d/usr.sbin.smbd
    aa-enforce /usr/sbin/smbd
    cat /etc/apparmor.d/usr.sbin.smbd | apparmor_parser -r
fi
systemctl restart smbd.service nmbd.service && psuccess "Restarted samba" || perror "Failed to restart samba"

