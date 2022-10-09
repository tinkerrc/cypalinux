#!/usr/bin/env bash
pkgchk() {
    if (dpkg-query -W -f='${Status}' $1 2>/dev/null | grep 'install ok installed' &>/dev/null); then
        if (($# > 1)); then
            pwarn "$1 is INSTALLED and $2 is $(systemctl is-active $2 2>/dev/null)"
        else
            pwarn "$1 is INSTALLED"
        fi
    else
        pignore "$1 is not installed"
    fi
}

pkgchk openssh-server sshd
pkgchk apache2 apache2
pkgchk mysql mysql
pkgchk php
pkgchk wordpress
pkgchk vsftpd vsftpd
pkgchk proftpd proftpd
pkgchk pure-ftpd pure-ftpd
pkgchk samba smbd
pkgchk bind9 named
pkgchk nginx nginx
pkgchk postgresql postgresql
pkgchk postfix postfix

if [[ -d /var/www ]]; then
    pwarn "/var/www found"
else
    pignore "/var/www not found"
fi

if command -v snap &>/dev/null; then
    pwarn "snap exists"
else
    pignore "snap does not exist"
fi

cat /etc/passwd | cut -f3 -d":" | sort -n | uniq -c | while read x ; do
    [[ -z ${x} ]] && break
    set - $x
    if [[ $1 > 1 ]]; then
        users=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/passwd | xargs`
        perror "Duplicate UID ($2): ${users}"
    fi
done

cat /etc/group | cut -f3 -d":" | sort -n | uniq -c | while read x ; do
    [[ -z ${x} ]] && break
    set - $x
    if [[ $1 > 1 ]]; then
        groups=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/group | xargs`
        perror "Duplicate GID ($2): ${groups}"
    fi
done

cat /etc/passwd | cut -f1 -d":" | sort -n | uniq -c | while read x ; do
    [[ -z ${x} ]] && break
    set - $x
    if [[ $1 > 1 ]]; then
        uids=`awk -F: '($1 == n) { print $3 }' n=$2 /etc/passwd | xargs`
        perror "Duplicate User Name ($2): ${uids}"
    fi
done

cat /etc/group | cut -f1 -d":" | sort -n | uniq -c | while read x ; do
    [[ -z ${x} ]] && break
    set - $x
    if [[ $1 > 1 ]]; then
        gids=`gawk -F: '($1 == n) { print $3 }' n=$2 /etc/group | xargs`
        perror "Duplicate Group Name ($2): ${gids}"
    fi
done

if grep -q "^shadow:[^:]*:[^:]*:[^:]+" /etc/group; then
    perror "Shadow group has users. Remove!!"
fi

if awk -F: '($4 == "42") { print }' /etc/passwd | grep -Eq '.*'; then
    perror "Shadow group has users. Remove!!"
fi

mod manual-pkgs
mod default-config

todo "Read recon report above (reminder: duplicate users/groups are best removed immediately)"
