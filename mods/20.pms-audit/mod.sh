#!/usr/bin/env bash
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

# Hacking tools / backdoors
banned=(hydra nmap zenmap john medusa vino ophcrack aircrack-ng fcrackzip nikto iodine kismet packit pcmpem goldeneye themole)
# Unnecessary packages
banned+=(empathy prelink minetest snmp nfs-kernel-server rsh-client talk squid nis talk portmap ldap-utils slapd tightvncserver inspircd ircd-hybrid ircd-irc2 ircd-ircu ngircd tircd znc sqwebmail cyrus-imapd dovecot-imapd)

banned=(empathy prelink minetest snmp nfs-kernel-server rsh-client talk squid nis talk portmap ldap-utils slapd tightvncserver inspircd ircd-hybrid ircd-irc2 ircd-ircu ngircd tircd znc sqwebmail cyrus-imapd dovecot-imapd)
for i in "${banned[@]}"; do
    if ! apt-cache madison $i &>/dev/null; then
        echo $i
    fi
done

apt remove -y ${banned[@]} || pwarn "Retrying removal in filtered mode" && aptr ${banned[@]} || perror "Failed to remove banned packages"
aptar
