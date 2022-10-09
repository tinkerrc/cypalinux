#!/usr/bin/env bash
echo 'nf_conntrack_ftp' >> /etc/modules
instsecret $RC/sysctl.conf /etc/sysctl.conf
sysctl -e -p /etc/sysctl.conf
mkdir -p $BACKUP/sysctl
mv /etc/sysctl.d/* $BACKUP/sysctl

instconf $RC/limits.conf /etc/security/limits.conf
instconf $RC/access.conf /etc/security/access.conf

psuccess "Installed system security configurations"

if [[ -f /etc/ld.so.preload ]]; then
    rm /etc/ld.so.preload && psuccess "Removed system-wide LD_PRELOAD"
fi 


pinfo "Securing RNG"
echo "HRNGDEVICE=/dev/urandom" >> /etc/default/rng-tools
systemctl restart rng-tools && psuccess "RNG service setup successful" || perror "Failed to set up RNG service"

pinfo "Disabling unnecessary protocols / kernel modules"

pinfo "Disabling unnecessary kernel modules..."
mods=(uvcvideo freevxfs jffs2 hfs hfsplus udf cramfs vivid bluetooth btusb dccp sctp rds tipc n-hdlc ax25 netrom x25 rose decnet econet af_802154 ipx appletalk psnap p8023 p8022 can atm)
for mod in "${mods[@]}"; do
    echo "install $mod /bin/false" >> /etc/modprobe.d/$mod.conf
    rmmod $mod -v
done
psuccess "Disabled unnecessary kernel modules"
