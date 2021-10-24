#!/usr/bin/env bash
set -u
#   ==================================
#   |     Linux Hardening Script     |
#   | Walnut HS Cyber Security Club  |
#   ==================================

# Save time by not typing sudo all the time
if [ ! "$(whoami)" = "root" ]; then
    echo "Please try again with root privileges..."
    return 1
fi

# Make sure the script was sourced, not run directly
if [ "${BASH_SOURCE[0]}" != "${0}" ]; then
    echo "Invoke harden to secure the machine"
else
    echo "Run 'source harden.sh' instead"
    return 1
fi

set -a # export all functions and variables
unalias -a

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
BASE="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &>/dev/null && pwd )"
DATA="$BASE/flags"
BACKUP="/backup"
DEBIAN_FRONTEND=noninteractive

mkdir -p $DATA
mkdir -p $BACKUP

if [[ -L /root/.bash_history ]]; then
    unlink /root/.bash_history
    echo '' > /root/.bash_history
fi

# ===================================
# Main functions
# ===================================

harden() {
    script -ac harden-impl "$DATA/log"
}
harden-impl() {
    echo "====| $(date '+%Y-%m-%d %H:%M:%S %Z') |====================>" >> "$DATA/log"
    echo "Walnut High School CSC CyberPatriot Linux Hardening Script"
    if ! [ -d "$BASE/rc" ]; then
        notify "The resources directory is missing"
        exit 1
    fi

    todo "Run 'setxkbmap -option caps:swapescape' as a regular user"
    todo "Launch two root shells in another terminal in case something goes wrong"
    todo "Change default user password to 'password'"

    basic-recon | tee "$BASE/recon"

    stg-config
    stg-fast
    stg-modules

    apt -y autoremove
    notify "The main script is finished. Consider invoking 'scan'."

    bash
}

pkgchk() {
    if (dpkg-query -W -f='${Status}' $1 2>/dev/null | grep 'install ok installed' &>/dev/null); then
        if (($# > 1)); then
            echo -e "\033[0;35;1;4m>>> $1 is INSTALLED and $2 is $(systemctl is-active $2 2>/dev/null)\033[0m"
        else
            echo "\033[0;35;1;4m$1 is INSTALLED\033[0m"
        fi
    else
        echo "$1 is NOT installed"
    fi
}

basic-recon() {
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

    if [ -d /var/www ]; then
        notify "/var/www found"
    else
        notify "/var/www not found"
    fi

    cat /etc/passwd | cut -f3 -d":" | sort -n | uniq -c | while read x ; do
        [ -z "${x}" ] && break
        set - $x
        if [ $1 -gt 1 ]; then
            users=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/passwd | xargs`
            notify "Duplicate UID ($2): ${users}"
        fi
    done

    cat /etc/group | cut -f3 -d":" | sort -n | uniq -c | while read x ; do
        [ -z "${x}" ] && break
        set - $x
        if [ $1 -gt 1 ]; then
            groups=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/group | xargs`
            notify "Duplicate GID ($2): ${groups}"
        fi
    done

    cat /etc/passwd | cut -f1 -d":" | sort -n | uniq -c | while read x ; do
        [ -z "${x}" ] && break
        set - $x
        if [ $1 -gt 1 ]; then
            uids=`awk -F: '($1 == n) { print $3 }' n=$2 /etc/passwd | xargs`
            notify "Duplicate User Name ($2): ${uids}"
        fi
    done

    cat /etc/group | cut -f1 -d":" | sort -n | uniq -c | while read x ; do
        [ -z "${x}" ] && break
        set - $x
        if [ $1 -gt 1 ]; then
            gids=`gawk -F: '($1 == n) { print $3 }' n=$2 /etc/group | xargs`
            notify "Duplicate Group Name ($2): ${gids}"
        fi
    done

    grep -q ^shadow:[^:]*:[^:]*:[^:]+ /etc/group && notify "SHADOW GROUP HAS USERS!! REMOVE!!"
    awk -F: '($4 == "42") { print }' /etc/passwd | grep -E '.*' && notify "SHADOW GROUP HAS USERS!! REMOVE!!"
    sleep 0.5
    todo "Read recon report above (also in $BASE/recon)"
}

stg-config() {
    notify "===== Configure ====="
    ready "Enter a list of authorized users"
    vim "$DATA/auth"

    read -rp "Is Apache a critical service? [y/N]" use_apache
    read -rp "Is MySQL a critical service? [y/n/I]" use_mysql
    read -rp "Is PHP a critical service? [y/N]" use_php
    read -rp "Is Wordpress a critical service? [y/N]" use_wordpress
    read -rp "Is postgresql a critical service? [y/n/I]" use_postgres

    read -rp "Is nginx a critical service? [y/n/I]" use_nginx

    read -rp "Is Pure-FTPD a critical service? [Y/n]" use_pureftpd
    read -rp "Is VSFTPD a critical service? [Y/n]" use_vsftpd
    read -rp "Is Pro-FTPD a critical service? [Y/n]" use_proftpd
    read -rp "Is Samba a critical service? [y/n/I]" use_samba

    read -rp "Is bind9 a critical service? [y/n/I]" use_bind9
    notify "Configuration complete."
    read -p "Press [ENTER] to start"
}
stg-fast() {
    install-apt-src
    backup
    install-deps
    cfg-dm
    cfg-unattended-upgrades
    cfg-sshd
    audit-fs
    firewall
    cfg-sys
    cfg-sudoer
    cfg-common
    cfg-fail2ban
    restrict-cron
    fix-file-perms
    audit-pkgs
    cfg-auditd
    # TODO: test
    #cfg-grub
}
stg-modules() {
    audit-users
    cfg-apache
    cfg-mysql
    cfg-php
    cfg-ftp
    cfg-bind9
    cfg-nginx
    cfg-postgresql
    cfg-samba
    cfg-dns
}

# ====================
# @helper
# ====================

red="\x1b[38;2;255;23;68m"
green="\x1b[38;2;0;230;118m"
gray="\x1b[38;2;189;189;189m"
purple="\x1b[38;2;234;128;252m"
orange="\x1b[38;2;255;61;0m"
reset="\x1b[0m"

echored() {
    echo -e "$red$*$reset"
}
echogreen() {
    echo -e "$green$*$reset"
}
echogray() {
    echo -e "$gray$*$reset"
}
echopurp() {
    echo -e "$purple$*$reset"
}
notify() {
    echo -e "$orange$*$reset"
}
todo () {
    # Follow the instruction; might have to leave terminal
    echo -e "${red}TODO:$reset $*"
    read -n 1 -rp "Press [ENTER] when you finish"
}
ready() {
    # Wait for user to be ready
    if [ "$*" != "" ]; then
        echo -e "${purple}READY:$reset $*"
    fi
    read -n 1 -rp "Press [ENTER] when you are ready"
}
act() {
    # Tell the user to do something manually
    if [ "$*" != "" ]; then
        echo -e "${}ACT:\033[0m $*"
    fi
}
do-task() {
    # in case the script is stopped midway
    # we don't have to go through everything again
    # unless it is not marked complete
    if [ -f "$DATA/$1" ]; then
        return
    fi
    echo -e "\033[0;32m-=-=-=-=-=-=-=-=-=-=-=-=\033[0m"
    echo -e "\033[0;32m| Task: $*\033[0m" | tr - ' '
    echo -e "\033[0;32m-=-=-=-=-=-=-=-=-=-=-=-=\033[0m"
    eval "$@"
    echo
    echo "Tip: Don't forget to record scoring reports and take notes!"
    # read -p "Done with the task? [yN] " -n 1 -r
    # echo; echo
    # if [[ $REPLY =~ ^[Yy]+$ ]]; then
    # NOTE: assumed yes
    sleep 0.3
    touch "$DATA/$1"
    # fi
}
restart-sshd() {
    systemctl restart sshd || service ssh restart
}

# ====================
# @fast
# ====================

install-apt-src() {
    local sources=""
    if (lsb_release -a 2>/dev/null | grep -q 16.04); then
        sources="$BASE/rc/sources.list.16"
    elif (lsb_release -a 2>/dev/null | grep -q 18.04); then
        sources="$BASE/rc/sources.list.18"
    elif (lsb_release -a 2>/dev/null | grep -q 'Debian 9'); then
        sources="$BASE/rc/sources.list.9"
    elif (lsb_release -a 2>/dev/null | grep -q 'Debian 10'); then
        sources="$BASE/rc/sources.list.10"
    fi
    cat "$sources" > /etc/apt/sources.list
    apt-key update -y
    apt update -y
}
backup() {
    notify "Backing up files..."
    mkdir -p "$BACKUP"
    cp -a /home "$BACKUP"
    cp -a /etc "$BACKUP"
    cp -a /var "$BACKUP"
}
install-deps() {
    if ! which vim &>/dev/null; then
        notify "Installing vim"
        apt install -y vim &>/dev/null
        notify "Installed vim"
    else
        notify "Vim is already installed"
    fi
    apt install -y gawk
}
cfg-dm() {
    if [ -d /etc/lightdm ]; then
        cat "$BASE/rc/lightdm.conf" > /etc/lightdm/lightdm.conf
    fi
    if [ -d /etc/gdm3 ]; then
        sed -i 's/^.*disable-user-list.*$/disable-user-list=true/' /etc/gdm3/greeter.dconf-defaults
        sed -i 's:^.*\[org/gnome/login-screen\].*$:[org/gnome/login-screen]:' /etc/gdm3/greeter.dconf-defaults
    fi
}
cfg-unattended-upgrades() {
    notify "Installing unattended-upgrades..."
    apt install -y unattended-upgrades
    local dir=/etc/apt/apt.conf.d
    mkdir -p "$dir" # should already be ther
    local file_pdc="10periodic"
    local file_uud="50unattended-upgrades"
    cat "$BASE/rc/$file_pdc" > "$dir/$file_pdc"
    cat "$BASE/rc/$file_uud" > "$dir/$file_uud"
    cat "$BASE/rc/$file_uud" > "$dir/20auto-upgrades"
}
cfg-sshd() {
    if ! [ -x /usr/bin/sshd ]; then
        notify "Installing openssh-server"
        apt install -y openssh-server
        notify "Installation complete"
    fi
    mv /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
    cp "$BASE/rc/sshd_config" /etc/ssh
    restart-sshd
    notify "New sshd_config applied"
}
audit-fs() {
    echo "tmpfs      /dev/shm    tmpfs   defaults,rw,noexec,nodev,nosuid,relatime   0 0" >> /etc/fstab
    echo "tmpfs      /tmp        tmpfs   defaults,rw,noexec,nodev,nosuid,relatime   0 0" >> /etc/fstab
    echo "tmpfs      /var/tmp    tmpfs   defaults,rw,noexec,nodev,nosuid,relatime   0 0" >> /etc/fstab
    local fss=(freevxfs jffs2 hfs hfsplus udf)
    for fs in "${fss[@]}"; do
        echo "install $fs /bin/true" >> /etc/modprobe.d/$fs.conf
        rmmod $fs -v
    done

    rm -f /home/*/.netrc
    rm -f /home/*/.forward
    rm -f /home/*/.rhosts
    if ! (which locate &>/dev/null); then
        notify "Installing locate utility"
        apt install -y mlocate findutils
    fi
    cat "$BASE/rc/updatedb.conf" > /etc/updatedb.conf
    notify "Updating database"
    updatedb

    mkdir -p "$BACKUP/quarantine"
    locate -0 -i --regex \
        "^/home/.*\.(aac|avi|flac|flv|gif|jpeg|jpg|m4a|mkv|mov|mp3|mp4|mpeg|mpg|ogg|png|rmvb|wma|wmv)$" | \
        grep -Ev '.config|.local|.cache|Wallpaper' | tee "$BASE/banned_files" | xargs -r0 mv -t "$BACKUP/quarantine" || notify "Couldn't remove files"
    locate -0 -i --regex \
        "\.(aac|avi|flac|flv|gif|jpeg|jpg|m4a|mkv|mov|mp3|mp4|mpeg|mpg|ogg|png|rmvb|wma|wmv)$" | \
        grep -Ev '^(/usr|/var/lib)' | tee "$BASE/sus_files"
    notify "Media files in /home are quarantined in $BACKUP/quarantine (see $BASE/banned_files)."
    notify "Also check $BASE/sus_files"
    sleep 2
}
firewall() {
    notify "Installing..."
    apt install -y ufw iptables
    chmod 751 /lib/ufw
    cp /etc/ufw/sysctl.conf "$BACKUP" 2>/dev/null
    cat "$BASE/rc/ufw-sysctl.conf" > /etc/ufw/sysctl.conf
    chmod 644 /etc/ufw/sysctl.conf
    ufw enable
    ufw --force reset
    ufw logging high
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw deny telnet
    ufw deny 2049
    ufw deny 515
    ufw deny 111
    notify "Allows outgoing traffic by default"
    notify "Denies incoming traffic by default"
    notify "Allow   :  SSH"
    notify "Reject  :  Telnet, 111, 555, 2049"
    ufw status verbose
}
cfg-sys() {
    cat "$BASE/rc/sysctl.conf" > /etc/sysctl.conf
    sysctl -e -p /etc/sysctl.conf
    sed -i 's/.*hard core.*//' /etc/security/limits.conf
    echo '* hard core 0' > /etc/security/limits.conf
    echo "/etc/sysctl.conf has been installed"
}
cfg-sudoer() {
    cp /etc/sudoers{,.bak}
    mv /etc/sudoers.d/* "$BACKUP"
    cat "$BASE/rc/sudoers" > /etc/sudoers
    notify "Sudoers audit complete"
}
cfg-common() {
    notify "Installing configuration files..."
    apt install -y libpam-cracklib libpam-pwquality
    cat "$BASE/rc/common-password" > /etc/pam.d/common-password
    cat "$BASE/rc/common-auth" > /etc/pam.d/common-auth
    cat "$BASE/rc/common-account" > /etc/pam.d/common-account
    cat "$BASE/rc/common-session" > /etc/pam.d/common-session
    cat "$BASE/rc/common-session-noninteractive" > /etc/pam.d/common-session-noninteractive
    cat "$BASE/rc/login.defs" > /etc/login.defs
    cat "$BASE/rc/host.conf" > /etc/host.conf
    cat "$BASE/rc/pwquality.conf" > /etc/security/pwquality.conf
    notify "PAM config, login.defs, and host.conf have been installed"
}
cfg-fail2ban() {
    apt install -y fail2ban
    touch /etc/fail2ban/jail.local
    cat "$BASE/rc/jail.local" > jail.local
    systemctl restart fail2ban || service fail2ban restart || notify "Failed to restart fail2ban"
}
restrict-cron() {
    notify "Backing up crontabs just to be sure"
    cp -r /var/spool/cron/ "$BACKUP/quarantine"
    notify "Setting allowed cron/at users to root"
    # only root can use cron & at
    echo "root" > /etc/cron.allow
    echo "root" > /etc/at.allow
    chmod 644 /etc/{cron,at}.allow
    systemctl restart cron
    notify "Done!"
}
fix-file-perms() {
    # TODO: set owner for /etc/ also?
    # 110 100 000
    # 6   4   0
    # rw- r-- ---
    chown root:root /etc
    chmod -R o-w /etc
    chown -R root:root /etc/default
    chmod 644 /etc/default/grub
    chown -R root:root /etc/grub.d
    chmod -R 755 /etc/grub.d/*_*
    chown -R root:root /boot/grub
    chmod 600 /boot/grub/grub.cfg

    chown root:root /
    chmod 751 /
    chmod 644 /etc/passwd
    chown root:root /etc/passwd
    chmod 644 /etc/passwd-
    chown root:root /etc/passwd-
    chmod 644 /etc/group
    chown root:root /etc/group
    chmod 644 /etc/group-
    chown root:root /etc/group-
    chmod 600 /etc/shadow
    chown root:root /etc/shadow
    chmod 600 /etc/shadow-
    chown root:root /etc/shadow-
    chmod 600 /etc/gshadow
    chown root:root /etc/gshadow
    chmod 600 /etc/gshadow-
    chown root:root /etc/gshadow-
    chmod 640 /etc/anacrontab
    chown root:root /etc/anacrontab
    chmod 640 /etc/crontab
    chown root:root /etc/crontab
    chmod 640 /etc/cron.hourly
    chown root:root /etc/cron.hourly
    chmod 640 /etc/cron.daily
    chown root:root /etc/cron.daily
    chmod 640 /etc/cron.weekly
    chown root:root /etc/cron.weekly
    chmod 640 /etc/cron.monthly
    chown root:root /etc/cron.monthly
    chmod 640 /etc/cron.d
    chown root:root /etc/cron.d
    chmod 700 /boot
    chmod 1777 /tmp
    chown root:root /tmp
    chmod 644 /etc/environment
    chown root:root /etc/environment
    chmod 644 /etc/login.defs
    chown root:root /etc/login.defs
    chmod 644 /etc/host*
    chown root:root /etc/host*
    chmod 777 /etc/resolv.conf
    chown root:root /etc/resolv.conf
    chmod 644 /etc/profile
    chown root:root /etc/profile
    chmod 664 /etc/fstab
    chown root:root /etc/fstab
    chmod 644 /etc/bash.*
    chown root:root /etc/bash.*
    chmod 400 /etc/sudoers
    chown root:root /etc/sudoers
    chmod 755 /etc/sudoers.d
    chown -R root:root /etc/sudoers.d
    chmod 440 /etc/sudoers.d/*
    chmod 755 /etc/ssh
    chown -R root:root /etc/ssh
    chmod 644 /etc/ssh/*
    chmod 755 /etc/php
    chown -R root:root /etc/php
    chmod 755 /etc/pam.d
    chown -R root:root /etc/pam.d
    chmod 644 /etc/pam.d/*
    chmod 755 /etc/default
    chown root:root /etc/default
    notify "Common system file permissions corrected"

    chmod 755 /home
    chmod 700 /home/*
    find /home -maxdepth 2 -mindepth 2 -name ".ssh" -type d -exec chmod 700 {} \; -print
    find /home -maxdepth 2 -mindepth 2 -name ".gnupg" -type d -exec chmod 700 {} \; -print
    find /home -maxdepth 3 -mindepth 2 -path "*.ssh*" -type f -exec chmod 600 {} \; -print
    find /home -maxdepth 3 -mindepth 2 -path "*.gnupg*" -type f -exec chmod 600 {} \; -print
    notify "Secured home and .ssh/* permissions"
}
disnow() {
    systemctl disable --now $1
}
add-crontab() {
    crontab -l > "$DATA/crontab"
    echo "$1" >> "$DATA/crontab"
    crontab "$DATA/crontab"
}
audit-pkgs() {
    disnow nfs-server
    disnow rpcbind
    disnow dovecot
    disnow squid
    disnow nis
    disnow snmpd
    disnow rsync
    prelink -ua

    # Hacking tools / backdoors
    local banned=(hydra\* frostwire vuze nmap zenmap john\* medusa vino ophcrack aircrack-ng fcrackzip nikto\* iodine kismet logkeys)
    # Unnecessary packages
    banned+=(empathy prelink minetest snmp\* nfs-\* rsh-\*client talk squid nis rsh-\* talk portmap ldap-\* tightvncserver ircd\* znc sqwebmail cyrus-\* dovecot\*)

    for pkg in "${banned[@]}"; do
        apt -y purge $pkg
    done

    apt -y install tcpd apparmor apparmor-profiles apparmor-utils clamav rkhunter chkrootkit software-properties-gtk auditd audispd-plugins aide aide-common ntp
    # TODO: test
    #aa-enforce /etc/apparmor.d/*
    #auditctl -e 1
    #auditctl -w /etc/shadow -k shadow-file -p rwxa
    #aideinit
    #add-crontab "0 5 * * * /usr/bin/aide.wrapper --config /etc/aide/aide.conf --check"
    apt -y autoremove
}
cfg-auditd() {
    # TODO: test
    #mkdir -p /etc/audit
    #cat "$BASE/rc/audit.rules" > /etc/audit/audit.rules
    #systemctl reload auditd
    :
}
cfg-grub() {
    cat <<EOF >/etc/grub.d/40_custom
#!/bin/sh
exec tail -n +3 $0
set check_signatures=enforce
export check_signatures
set superusers="root"
password_pbkdf2 root grub.pbkdf2.sha512.10000.F3F2D81BB5BF66BB56CC88C41519B91CA92FBA2AF16A04E7E381C525603F2E1DF1F40BAE5DD8731791B2D8D8CD4E4681B1E12047582E7533FE4D4D4B0C982FFE.00BEAB2F9E09CBF5A8225882CE7E527D54AFC1E2D5C98D3AC59A8DED05D047BD7E304D6AD3682210270A66F43CC5922FEF7FAE583885063F9DDBCF8897B3A80F
EOF
    sed -i 's/^CLASS="--class gnu-linux --class gnu --class os"$/CLASS="--class gnu-linux --class gnu --class os --unrestricted"/' /etc/grub.d/10_linux
    update-grub
}
audit-users() {
    usermod -g 0 root
    notify 'Change passwords (might take a while)...'
    sed '/^$/d;s/^ *//;s/ *$//;s/$/:Password123!/' "$DATA/auth" | chpasswd
    notify 'Change passwords (might take a while)... Done'
    awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd > "$DATA/check"
    python3 "$BASE/rmusers.py" "$DATA"
    gawk -i inplace -F: '$3 != 0 || ($3 == 0 && $1 == "root") {print $0}' /etc/passwd
    for user in `awk -F: '($3 < 1000) {print $1 }' /etc/passwd`; do
        if [ $user != "root" ]; then
            usermod -L $user
            if [ $user != "sync" ] && [ $user != "shutdown" ] && [ $user != "halt" ]; then
                usermod -s /usr/sbin/nologin $user
            fi
        fi
    done
    notify "User audit complete"
}

# ====================
# @modules
# ====================

cfg-ftp() {
    if [[ $use_pureftpd =~ ^[Nn]+$ ]]; then
        notify "Removing Pure-FTPD"
        disnow pure-ftpd
        apt -y remove pure-ftpd
    else
        ufw allow ftp
        ufw allow ftps
        notify "Installing Pure-FTPD"
        apt install -y pure-ftpd

        cp /etc/pure-ftpd/conf{,.bak}
        rm -rf /etc/pure-ftpd/conf
        cat "$BASE/rc/pure-ftpd.conf" > /etc/pure-ftpd/pure-ftpd.conf

        mkdir /etc/pure-ftpd/conf
        echo "2" > /etc/pure-ftpd/conf/TLS
        echo "yes" > /etc/pure-ftpd/conf/NoAnonymous
        echo "no" > /etc/pure-ftpd/conf/AnonymousOnly
        echo "no" > /etc/pure-ftpd/conf/UnixAuthentication
        echo "yes" > /etc/pure-ftpd/conf/PAMAuthentication
        echo "no" > /etc/pure-ftpd/conf/ChrootEveryone
        echo "HIGH" > /etc/pure-ftpd/conf/TLSCipherSuite
        echo "/etc/pure-ftpd/pureftpd.pdb" > /etc/pure-ftpd/conf/PureDB
        echo "clf:/var/log/pure-ftpd/transfer.log" > /etc/pure-ftpd/conf/AltLog
        echo "UTF-8" > /etc/pure-ftpd/conf/FSCharset
        echo "1000" > /etc/pure-ftpd/conf/MinUID

        if ! [ -f /etc/ssl/private/pure-ftpd.pem ]; then
            mkdir -p /etc/ssl/private
            sudo openssl req -x509 -nodes -days 7300 -newkey rsa:2048 -keyout /etc/ssl/private/pure-ftpd.pem -out /etc/ssl/private/pure-ftpd.pem
        fi
        chmod 600 /etc/ssl/private/pure-ftpd.pem
        chmod -R o-r /etc/pure-ftpd
        chown -R root:root /etc/pure-ftpd

        systemctl restart pure-ftpd
    fi

    if [[ $use_vsftpd =~ ^[Nn]+$ ]]; then
        notify "Removing VSFTPD"
        disnow vsftpd
        apt -y remove vsftpd
    else
        ufw allow ftp
        ufw allow ftps
        apt install -y vsftpd

        cp /etc/vsftpd.conf{,.bak}
        cp "$BASE/rc/vsftpd.conf" /etc/vsftpd.conf

        if ! [ -f /etc/ssl/private/vsftpd.key ]; then
            mkdir -p /etc/ssl/private
            openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/vsftpd.key -out /etc/ssl/certs/vsftpd.crt
        fi
        chmod 600 /etc/ssl/private/vsftpd.key
        chown -R root:root /etc/vsftpd*

        systemctl restart vsftpd
    fi

    if [[ $use_proftpd =~ ^[Nn]+$ ]]; then
        notify "Removing Pro-FTPD"
        disnow proftpd
        apt -y remove proftpd
    else
        ufw allow ftp
        ufw allow ftps
        apt install -y proftpd

        cp /etc/proftpd/proftpd.conf{,.bak}
        cat "$BASE/rc/proftpd.conf" > /etc/proftpd/proftpd.conf
        cat "$BASE/rc/tls.conf" > /etc/proftpd/tls.conf

        if ! [ -f /etc/ssl/private/proftpd.key ]; then
            mkdir -p /etc/ssl/private
            openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/proftpd.key -out /etc/ssl/certs/proftpd.crt
        fi
        chmod 600 /etc/ssl/private/proftpd.key
        chown -R root:root /etc/proftpd

        systemctl restart proftpd
    fi
}
cfg-apache() {
    if [[ $use_apache =~ ^[^Yy]+$ ]]; then
        apt -y remove apache2
    else
        apt install -y apache2 libapache2-mod-{security2,evasive,php}
        notify "Configuring apache2"
        cp /etc/apache2/apache2.conf{,.bak}
        cat "$BASE/rc/apache2.conf" > /etc/apache2/apache2.conf
        cat "$BASE/rc/wordpress.conf" > /etc/apache2/sites-available/wordpress.conf
        cat "$BASE/rc/security.conf" > /etc/apache2/conf-available/security.conf
        cat "$BASE/rc/modsecurity.conf" > /etc/modsecurity/modsecurity.conf
        cat "$BASE/rc/crs-setup.conf" > /usr/share/modsecurity-crs/crs-setup.conf
        cat "$BASE/rc/security2.conf" > /etc/apache2/mods-available/security2.conf
        chown -R root:root /etc/apache2
        chmod 755 /etc/apache2
        chmod -R o-r /etc/apache2
        chmod -R 750 /etc/apache2/bin
        chmod -R 750 /etc/apache2/conf
        ln -s /usr/share/wordpress /var/www/html/wordpress
        a2enconf security
        a2dissite 000-default
        a2ensite wordpress
        a2enmod rewrite security2 evasive headers unique_id
        a2dismod -f include imap info userdir autoindex dav dav_fs
        mkdir -p /var/cache/modsecurity/uploads
        chmod -R 750 /var/cache/modsecurity
        ufw allow http
        ufw allow https
        systemctl reload apache2
        notify "Successfully configured Apache2"
    fi
}
cfg-mysql() {
    ufw deny mysql
    if [[ $use_mysql =~ ^[Yy]+$ ]]; then
        apt install -y mysql-server
        cp -r /etc/mysql "$BACKUP"
        echo -e "[mysqld]\nbind-address = 127.0.0.1\nskip-show-database\nskip-networking" > /etc/mysql/mysql.conf.d/mysqld.cnf
        echo -e "[mysql]\nlocal-infile=0" > /etc/mysql/conf.d/mysql.cnf
        chmod -R root:root /etc/mysql
        systemctl restart mysql

        grep -rn "skip-grant-tables" /etc/mysql

        todo "add password to all users (incl. mysql & root)"
        todo "check if users have the right privileges"
        systemctl restart mysql
    elif [[ $use_mysql =~ ^[Nn]+$ ]]; then
        disnow mysql
        apt -y remove mysql
    else
        notify "No action taken"
    fi
}
cfg-php() {
    if [[ $use_php =~ ^[^Yy]+$ ]]; then
        apt remove -y php
    else
        apt install -y php{,-mysql,-cli,-cgi,-gd}
        cat "$BASE/rc/php.ini" > /etc/php/7.0/cli/php.ini
        php --ini
        chown -R root:root /etc/php
    fi
}
cfg-wordpress() {
    if [[ $use_wordpress =~ ^[^Yy]+$ ]]; then
        apt remove -y wordpress
    else
        apt install -y wordpress
        gzip -d /usr/share/doc/wordpress/examples/setup-mysql.gz
        bash /usr/share/doc/wordpress/examples/setup-mysql -n wordpress localhost
        chown -R www-data:www-data /var/www/
        chown -R www-data /usr/share/wordpress
        find /var/www -type d -exec chmod 775 {} \;
        find /usr/share/wordpress -type d -exec chmod 775 {} \;
        [[ $use_apache =~ ^[Yy]+$ ]] && systemctl restart apache2
    fi
}
cfg-bind9() {
    if [[ $use_bind9 =~ ^[Yy]+$ ]]; then
        apt install -y bind9
        sed -i 's/^.*version\s+".*";.*/version none;/' /etc/bind/named.conf.options
        sed -i 's/^.*allow-transfer.*;.*/allow-transfer {none;};/' /etc/bind/named.conf.options
        chmod -R o-r /etc/bind
    elif [[ $use_bind9 =~ ^[Nn]+$ ]]; then
        disnow named
        apt -y remove bind9
    else
        notify "Will not remove bind9"
    fi

}
cfg-nginx() {
    if [[ $use_nginx =~ ^[Yy]+$ ]]; then
        ufw enable http
        ufw enable https
    elif [[ $use_nginx =~ ^[Nn]+$ ]]; then
        disnow nginx
        apt -y remove nginx
    else
        notify "Will not remove nginx"
    fi
}
cfg-postgresql() {
    if [[ $use_postgres =~ ^[Yy]+$ ]]; then
        apt install -y postgresql{,-contrib}
    elif [[ $use_postgres =~ ^[Nn]+$ ]]; then
        disnow postgresql
        apt -y remove postgresql
    else
        notify "Will not remove postgresql"
    fi
}
cfg-samba() {
    if [[ $use_samba =~ ^[Yy]+$ ]]; then
        apt install samba libpam-winbind
        sed -i 's/^.*guest ok.*$/    guest ok = no/' /etc/samba/smb.conf
        sed -i 's/^.*usershare allow guests.*$/usershare allow guests = no/' /etc/samba/smb.conf
        mkdir -p /etc/apparmor.d
        cat <<'EOF' > /etc/apparmor.d/usr.sbin.smbd
  /srv/samba/share/ r,
  /srv/samba/share/** rwkix,
EOF
        aa-enforce /usr/sbin/smbd
        cat /etc/apparmor.d/usr.sbin.smbd | apparmor_parser -r
        systemctl restart smbd.service nmbd.service
    elif [[ $use_samba =~ ^[Nn]+$ ]]; then
        notify "Removing samba"
        systemctl disable --now smbd.service nmbd.service
        apt -y remove samba
    else
        notify "No actions taken"
    fi
}
cfg-dns() {
#    cat <<'EOF' >/etc/systemd/resolved.conf
#[Resolve]
#DNS=8.8.8.8 8.8.4.4
#EOF
#    systemctl daemon-reload
#    systemctl restart systemd-{networkd,resolved}
    notify "Done configuring DNS/resolved"
}

# ====================
# @scan
# ====================

scan () {
    do-task run-lynis
    do-task run-linenum
    do-task run-linpeas
    do-task av-scan
}
run-lynis() {
    cd "$DATA"
    if ! [[ -d "$DATA/lynis" ]]; then
        git clone --depth 1 https://github.com/CISOfy/lynis
    fi
    cd lynis
    clear
    ready "Start lynis"
    ./lynis audit system --quiet
    ready "Take action in bash; run lynis under other modes if necessary"
    bash
}
run-linenum() {
    cd "$DATA"
    if ! [[ -d "$DATA/LinEnum" ]]; then
        git clone https://github.com/rebootuser/LinEnum
    fi
    cd LinEnum
    chmod u+x ./LinEnum.sh
    ./LinEnum.sh -t -e "$DATA" -r enum
    less enum
    ready "Take action in bash"
    bash
}
run-linpeas() {
    cd "$DATA"
    if ! [[ -d "$DATA/peas" ]]; then
        git clone --depth 1 https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/ peas
    fi
    ready "Run linpeas.sh"
    ./peas/linPEAS/linpeas.sh -a
    ready "Inspect"
    bash
}
av-scan() {
    notify "--AV Scans--"
    ready "Start chkrootkit scan"
    chkrootkit -q

    ready "Start rkhunter scan"
    rkhunter --update
    rkhunter --propupd
    rkhunter -c --enable all --disable none

    ready "Start ClamAV scan"
    freshclam --stdout
    clamscan -r --bell -i --stdout --exclude-dir="^/sys" /
}
