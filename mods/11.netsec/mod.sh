# TODO: maybe move this part to 11.ufw/use.sh b/c other types of firewalls are available (nftables, etc)
# TODO: inspect /etc/hosts file
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

instconf $RC/interfaces /etc/network/interfaces
instconf $RC/nsswitch.conf /etc/nsswitch.conf
instconf $RC/host.conf /etc/host.conf
instconf $RC/hosts /etc/hosts
echo "127.0.0.1 localhost $(hostname)" >> /etc/hosts
psuccess "Resolver configurations installed"

rm -f /home/*/.netrc
rm -f /home/*/.forward
rm -f /home/*/.rhosts
psuccess "Removed rsh artifacts"
