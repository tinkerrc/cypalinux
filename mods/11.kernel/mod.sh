instsecret $RC/sysctl.conf /etc/sysctl.conf
sysctl -e -p /etc/sysctl.conf
mkdir -p $BACKUP/sysctl
mv /etc/sysctl.d/* $BACKUP/sysctl

instconf $RC/limits.conf /etc/security/limits.conf

psuccess "Installed kernel security configurations"
