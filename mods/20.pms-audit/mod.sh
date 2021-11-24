disnow nfs-server
disnow rpcbind
disnow dovecot
disnow squid
disnow nis
disnow snmpd
disnow rsync
disnow postfix
update-rc.d postfix disable
prelink -ua

# TODO: remove nonexistent packages and don't use aptr because locally installed packages will be covered by manual inspection
# Hacking tools / backdoors
banned=(hydra frostwire vuze nmap zenmap john medusa vino ophcrack aircrack-ng fcrackzip nikto iodine kismet logkeys)
# Unnecessary packages
banned+=(empathy prelink minetest snmp nfs-kernel-server rsh-client talk squid nis talk portmap ldap-utils slapd tightvncserver inspircd ircd-hybrid ircd-irc2 ircd-ircu ngircd tircd znc sqwebmail cyrus-imapd dovecot-imapd)

aptr ${banned[@]}
aptar

# TODO: move into other modules' pkglist
