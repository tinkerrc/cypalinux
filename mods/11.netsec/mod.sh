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

# TODO: set up tcpd
# TODO: set up ntpd
