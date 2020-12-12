#!/usr/bin/env bash
set -u
#   ==================================
#   |     Linux Hardening Script     |
#   | Walnut HS Cyber Security Club  |
#   ==================================

if [ ! "$(whoami)" = "root" ]; then
    echo "Please try again with root privileges..."
    return 1
fi

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
        echo "The resources directory is missing"
        exit 1
    fi

    ready "Run 'setxkbmap -option caps:swapescape' as a regular user (optional)"

    basic-recon | tee "$BASE/recon"

    todo "Launch a root shell in another terminal in case something goes wrong"
    section-streamline
    section-common
    section-regular
    section-rare

    apt autoremove
    echo "Done!"

    bash
}

pkgchk() {
    if (dpkg-query -W -f='${Status}' $1 2>/dev/null | grep 'ok installed' &>/dev/null); then
        if [[ "$2" != "" ]]; then
            echo "\033[0;35;1;4mREADY:\033[0m $*"
            echo -e "\033[0;35;1;4m>>> $1 is INSTALLED and $2 is $(systemctl is-active $2 2>/dev/null)\033[0m"
        else
            echo "$1 is INSTALLED"
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
    pkgchk vsftpd vsftpd
    pkgchk proftpd proftpd
    pkgchk pure-ftpd pure-ftpd
    pkgchk samba smbd
    pkgchk bind9 named
    pkgchk nginx nginx
    pkgchk postgresql postgresql
    if [ -d /var/www ]; then
        echo "/var/www found"
    else
        echo "/var/www not found"
    fi
    todo "Read recon report above (also in $BASE/recon)"
}

section-streamline() {
    install-apt-src
    backup
    ensure-vim
    ensure-python3
    fast-cfg-dm
    cfg-unattended-upgrades
    cfg-sshd
    fast-audit-fs
    firewall
    cfg-sys
    cfg-sudoer
    cfg-common
    cfg-fail2ban
    restrict-cron
    fix-file-perms
    fast-audit-pkgs
    cfg-auditd
}
section-common() {
    todo "Read the README before proceeding"
    todo "Do Forensics Questions"
    firefox-config
    do-task user-audit
    do-task inspect-passwd
    do-task inspect-group
    do-task cfg-dm
    lock-root
    chsh-root
    do-task find-pw-text-files
    do-task audit-fs
    do-task audit-pkgs
}
section-regular() {
    do-task inspect-svc
    do-task cfg-lamp
    do-task cfg-ftp
    do-task cfg-bind9
    do-task cfg-nginx
    do-task cfg-postgresql
    do-task cfg-samba
    do-task inspect-www
    do-task inspect-cron
    do-task inspect-ports
    do-task inspect-netcat
}
section-rare() {
    do-task inspect-apt-src
    do-task inspect-file-attrs
    do-task inspect-hosts
    do-task inspect-resolv
    do-task inspect-startup
    do-task inspect-unit-files
    do-task secure-fs
    do-task view-ps
    todo "Source harden.sh and invoke scan in a new terminal window"
    do-task suggestions
}

# ====================
# Helper functions
# ====================

todo () {
    # Follow the instruction; might have to leave terminal
    echo -e "\033[0;31;1;4mTODO:\033[0m $*"
    read -n 1 -rp "Press [ENTER] when you finish"
}
ready() {
    # Wait for user to be ready
    if [ "$*" != "" ]; then
        echo -e "\033[0;35;1;4mREADY:\033[0m $*"
    fi
    sleep 0.75
    # NOTE: disabled read
    #read -n 1 -rp "Press [ENTER] when you are ready"
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
    # if [[ $REPLY =~ ^[Yy]$ ]]; then
    # NOTE: assumed yes
        sleep 0.3
        touch "$DATA/$1"
    # fi
}
restart-sshd() {
    echo "Restarting sshd"
    if ! (systemctl restart sshd || service ssh restart); then
        echo "Failed to restart sshd"
        ready "Ensure sshd is running"
        bash
    else
        echo "Successfully restarted sshd"
    fi
}

# ====================
# @streamline
# ====================

install-apt-src() {
    if (lsb_release -a 2>/dev/null | grep -q 16.04); then
        cat "$BASE/rc/sources.list.16" > /etc/apt/sources.list
    elif (lsb_release -a 2>/dev/null | grep -q 18.04); then
        cat "$BASE/rc/sources.list.18" > /etc/apt/sources.list
    else
        cat "$BASE/rc/sources.list.9" > /etc/apt/sources.list
    fi
    apt-key update -y
    apt update -y
}
backup() {
    echo "Backing up files..."
    cp -a /home "$BACKUP" || true
    cp -a /etc "$BACKUP" || true
    cp -a /var "$BACKUP" || true
    if [ -d "$BACKUP" ]; then
        echo "NOTE: /etc /var and /home are backed up into $BACKUP"
        ready "Double check the files"
        cd "$BACKUP"
        bash
        cd "$BASE"
    else
        echo "Backup failed; $BACKUP not found"
    fi
}
ensure-vim() {
    if ! which vim &>/dev/null; then
        echo "Installing vim"
        apt install -y vim &>/dev/null
        echo "Installed vim"
    else
        echo "Vim is already installed"
    fi
}
ensure-python3() {
    echo "Checking python3 installation..."
    if ! (python3 --version >/dev/null); then
        ready "Try installing python3"
        bash
    else
        echo "Python3 is installed."
    fi
}
fast-cfg-dm() {
    if [ -d /etc/lightdm ]; then
        echo > "$DATA/lightdmconf" # clear file
        while read -r line
        do
            if [[ ! $line =~ ^allow-guest=[a-z]+ ]]; then
                echo "$line" >> "$DATA/lightdmconf"
            fi
        done < <(cat /etc/lightdm/lightdm.conf /usr/share/lightdm/lightdm.conf /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf 2>/dev/null)
        {
            echo "[Seat:*]"
            echo "allow-guest=false"
            echo "greeter-hide-users=true"
            echo "greeter-show-manual-login=true"
            echo "autologin-guest=false"
        } >> "$DATA/lightdmconf"
        cat "$DATA/lightdmconf" > /etc/lightdm/lightdm.conf
        cat "$DATA/lightdmconf" > /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf
    fi
    sed -i 's/^.*disable-user-list.*$/disable-user-list=true/' /etc/gdm3/greeter.dconf-defaults
    cat <<'EOF' > /etc/dconf/profile/gdm
user-db:user
system-db:gdm
file-db:/usr/share/gdm/greeter-dconf-defaults
EOF

    cat <<'EOF' > /etc/dconf/db/gdm.d/00-login-screen
[org/gnome/login-screen]
# Do not show the user list
disable-user-list=true
EOF

    dconf update
}
cfg-unattended-upgrades() {
    echo "Installing unattended-upgrades..."
    apt install -y unattended-upgrades
    dir=/etc/apt/apt.conf.d
    mkdir -p "$dir" # should already be ther
    file_pdc="10periodic"
    file_uud="50unattended-upgrades"
    cat "$BASE/rc/$file_pdc" > "$dir/$file_pdc"
    cat "$BASE/rc/$file_uud" > "$dir/$file_uud"
}
cfg-sshd() {
    if ! [ -x /usr/bin/sshd ]; then
        echo "Installing openssh-server"
        apt install -y openssh-server
        echo "Installation complete"
    fi
    mv /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
    cp "$BASE/rc/sshd_config" /etc/ssh
    restart-sshd
    echo "New sshd_config applied"
}
fast-audit-fs() {
    rm -f /home/*/.netrc
    rm -f /home/*/.forward
    rm -f /home/*/.rhosts
    if ! (which locate &>/dev/null); then
        echo "Installing locate utility"
        apt install -y mlocate findutils
    fi
    cat "$BASE/rc/updatedb.conf" > /etc/updatedb.conf
    echo "Updating database"
    updatedb

    if ! [ -d "$BACKUP/home" ]; then
        echo "Warning: backup for home not found"
        read -n 1 -rp "Press [ENTER] to continue"
    fi
    mkdir -p "$BACKUP/quarantine"
    locate -0 -i --regex \
        "^/home/.*\.(aac|avi|flac|flv|gif|jpeg|jpg|m4a|mkv|mov|mp3|mp4|mpeg|mpg|ogg|png|rmvb|wma|wmv)$" | \
        tee "$BASE/banned_files" | xargs -0 -t mv -t "$BACKUP/quarantine" || echo "Couldn't remove files"
    locate -0 -i --regex \
        "\.(aac|avi|flac|flv|gif|jpeg|jpg|m4a|mkv|mov|mp3|mp4|mpeg|mpg|ogg|png|rmvb|wma|wmv)$" | \
        grep -Ev '^(/usr|/var/lib)' | tee "$BASE/sus_files"
    echo "Media files in /home are quarantined in $BACKUP/quarantine (see $BASE/banned_files)."
    echo "Also check $BASE/sus_files"
    sleep 2
}
firewall() {
    echo "Installing..."
    apt install -y ufw iptables
    chmod 751 /lib/ufw
    ufw enable
    ufw logging high
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw deny telnet
    ufw deny 2049
    ufw deny 515
    ufw deny 111
    echo "Allows outgoing traffic by default"
    echo "Denies incoming traffic by default"
    echo "Allow   :  SSH"
    echo "Reject  :  Telnet, 111, 555, 2049"
    ufw status verbose
    if [ -f /etc/ufw/sysctl.conf ]; then
        cp /etc/ufw/sysctl.conf "$BACKUP"
        sed 's:\.:/:g' "$BASE/rc/sysctl.conf" > /etc/ufw/sysctl.conf
    fi
}
cfg-sys() {
    cat "$BASE/rc/sysctl.conf" > /etc/sysctl.conf
    sysctl -e -p /etc/sysctl.conf
    grep "hard core" /etc/security/limits.conf /etc/security/limits.d/*
    sed -i 's/.*hard core.*//' /etc/security/limits.conf
    echo '* hard core 0' > /etc/security/limits.conf
    echo "/etc/sysctl.conf has been installed"
}
cfg-sudoer() {
    cp /etc/sudoers{,.bak}
    cat "$BASE/rc/sudoers" > /etc/sudoers
    echo "Sudoers audit complete"
}
cfg-common() {
    echo "Installing configuration files..."
    apt install -y libpam-cracklib libpam-pwquality
    cat "$BASE/rc/common-password" > /etc/pam.d/common-password
    cat "$BASE/rc/common-auth" > /etc/pam.d/common-auth
    cat "$BASE/rc/common-account" > /etc/pam.d/common-account
    cat "$BASE/rc/common-session" > /etc/pam.d/common-session
    cat "$BASE/rc/common-session-noninteractive" > /etc/pam.d/common-session-noninteractive
    cat "$BASE/rc/login.defs" > /etc/login.defs
    cat "$BASE/rc/host.conf" > /etc/host.conf
    cat "$BASE/rc/pwquality.conf" > /etc/security/pwquality.conf
    echo "PAM config, login.defs, and host.conf have been installed"
}
cfg-fail2ban() {
    apt install -y fail2ban
    touch /etc/fail2ban/jail.local
    cat "$BASE/rc/jail.local" > jail.local
    systemctl restart fail2ban || service fail2ban restart || echo "Failed to restart fail2ban"
}
restrict-cron() {
    echo "Setting allowed cron/at users to root"
    crontab -r # reset crontabs
    # only root can use cron & at
    echo "root" > /etc/cron.allow
    echo "root" > /etc/at.allow
    chmod 644 /etc/{cron,at}.allow
    systemctl restart cron
    echo "Done!"
}
fix-file-perms() {
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
    echo "Common system file permissions corrected"

    chmod 755 /home
    chmod 700 /home/*
    find /home -maxdepth 2 -mindepth 2 -name ".ssh" -type d -exec chmod 700 {} \; -print
    # assuming there's no funny business going on in .ssh/, should only have files
    # not directories
    find /home -maxdepth 3 -mindepth 2 -path "*.ssh*" -type f -exec chmod 600 {} \; -print
    echo "Secured home and .ssh/* permissions"
    echo "Inspection complete"
}
disnow() {
    systemctl disable --now $1
}
fast-audit-pkgs() {
    disnow avahi-daemon
    disnow cups
    disnow nfs-server
    disnow rpcbind
    disnow dovecot
    disnow squid
    disnow nis
    prelink -ua
    apt -my --ignore-missing purge hydra* nmap zenmap john* netcat* build-essential
    apt -my --ignore-missing purge medusa vino ophcrack minetest aircrack-ng fcrackzip nikto*
    apt -my --ignore-missing purge prelink nfs-* portmap squid rsync nis rsh-* talk telnet ldap-*
    apt -y install apparmor apparmor-profiles apparmor-utils clamav rkhunter chkrootkit software-properties-gtk auditd audispd-plugins aide aide-common ntp chrony
    auditctl -w /etc/shadow -k shadow-file -p rwxa
    aideinit
    apt -y autoremove
}
cfg-auditd() {
    mkdir -p /etc/audit
    cat "$BASE/rc/audit.rules" > /etc/audit/audit.rules
    systemctl reload auditd
}

# ====================
# @common
# ====================

firefox-config() {
    apt -y purge firefox &>/dev/null
    apt -y install firefox
    # TODO: add user.js (?)

    todo "Configure Firefox; remember to set as default browser"
}
user-audit() {
    usermod -g 0 root
    ready "Enter a list of authorized users"
    vim "$DATA/auth"
    sed "s/$/: Password123!/" "$DATA/auth" | chpasswd
    # TODO: ask for autologin username and prevent pw change
    # TODO: automate group fixing here and remove inspect-group
    awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd > "$DATA/check"
    python3 "$BASE/rmusers.py" "$DATA/auth" "$DATA/check" "$DATA/unauth"
    for user in `awk -F: '($3 < 1000) {print $1 }' /etc/passwd`; do
        if [ $user != "root" ]; then
            usermod -L $user
            if [ $user != "sync" ] && [ $user != "shutdown" ] && [ $user != "halt" ]; then
                usermod -s /usr/sbin/nologin $user
            fi
        fi
    done
    echo "User audit complete"
}
inspect-passwd() {
    grep :0: /etc/passwd
    ready "Inspect abnormal users (eg. UID 0, weird shell/home)"
    vim /etc/passwd
    echo "/etc/passwd inspection complete"
}
inspect-group() {
    # TODO: set sudo users automatically
    grep adm /etc/group
    grep sudo /etc/group
    echo "sudo,adm,admin,wheel"
    ready "Inspect groups"
    vim /etc/group
    echo "/etc/group inspection complete"
}
cfg-dm() {
    echo "LightDM: /etc/lightdm/ and /usr/share/lightdm/lightdm.conf.d/"
    echo "GDM: /etc/gdm/*, disable-user-list=true in greeter conf"
    ready "Inspect DM config" # TODO: automate
    echo "Note: currently using $(grep '/usr/s\?bin' /etc/systemd/system/display-manager.service | cut -d= -f2 | cut -d/ -f4)"
    bash
}
lock-root() {
    read -p "Lock the root account? [yN] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        passwd -l root
        echo "root account locked"
    else
        echo "root account not locked"
    fi
}
chsh-root() {
    read -p "Change root shell to /usr/sbin/nologin? [yN] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        chsh -s "$(which nologin)" root
    else
        echo "root shell not changed"
    fi
}
find-pw-text-files() {
    # TODO: automate; find password.*; grep -rn PASSWORD /home
    echo '--- Potential Password Files Start ---'
    find /home -name "*pass*"
    find /home -name "*pw*"
    echo '---  Potential Password Files End  ---'
    ready "Try to find and quarantine (e.g., cd /home; grep -rwni P@a5w0rD)"
    bash
}
audit-fs() {
    ls /home/*
    ready "Look for suspicious files"
    bash
}
audit-pkgs() {
    if (which software-properties-gtk &>/dev/null); then
        todo "Launch software-properties-gtk (Software & Updates)"
    fi
    dpkg-reconfigure postfix
    echo '--- Manually Installed Packages Start ---'
    comm -23 <(apt-mark showmanual | sort -u) <(gzip -dc /var/log/installer/initial-status.gz | sed -n 's/^Package: //p' | sort -u) | tee "$BASE/manually-installed"
    echo '---  Manually Installed Packages End  ---'
    echo
    echo '---      Non-base packages Start      ---'
    apt list --installed | grep -vxf "$BASE/rc/pkgorig.txt" | tee "$BASE/nonbase-pkgs"
    echo '---       Non-base packages End       ---'
    ready "Inspect and remove packages listed above if necessary (see $BASE/manually-installed and $BASE/nonbase-pkgs)"
    bash

    # TODO: async OR just do it manually :)
    apt -y update
    apt -y dist-upgrade
}

# ====================
# @regular
# ====================

inspect-svc() {
    echo "Inspect services"
    if which service &>/dev/null; then
        echo " [+] : running"
        echo " [-] : stopped"
        echo " [?] : upstart service / status unsupported"
        service --status-all | sort
    fi
    ready "Inspect services and systemd units in /etc/systemd and /home/**/.config/systemd"
    bash
}
cfg-ftp() {
    read -n 1 -rp "Is Pure-FTPD a critical service? [Yn]"
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        echo "Removing Pure-FTPD"
        apt autoremove -y --purge pure-ftpd
        ufw deny ftp
        ufw deny ftps
    else
        ufw allow ftp
        ufw allow ftps
        echo "Installing Pure-FTPD"
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

        systemctl restart pure-ftpd
    fi

    read -n 1 -rp "Is VSFTPD a critical service? [Yn]"
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        echo "Removing VSFTPD"
        apt autoremove --purge vsftpd
        ufw deny ftp
        ufw deny ftps
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

        systemctl restart vsftpd
    fi

    read -n 1 -rp "Is Pro-FTPD a critical service? [Yn]"
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        echo "Removing Pro-FTPD"
        apt autoremove --purge proftpd
        ufw deny ftp
        ufw deny ftps
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

        systemctl restart proftpd
        todo "Check /etc/proftpd/conf.d for conflicting configurations"
    fi
}
cfg-lamp() {
    ufw deny mysql
    read -n1 -rp "Is LAMP necessary? [ynI]"
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        apt purge -y mysql-server
        apt install -y wordpress apache2 libapache2-mod-{security2,evasive,php} mysql-server php{,-mysql,-cli,-cgi,-gd}
        cfg-apache
        cfg-mysql
        cfg-php
        cfg-wordpress
    elif [[ $REPLY =~ ^[Nn]$ ]]; then
        ufw deny http
        ufw deny https
        apt --ignore-missing autoremove --purge -y php* mysql* apache2* libapache2* wordpress*
        rm -rf /var/www/*
    else
        echo "No actions taken"
    fi
}
cfg-apache() {
    echo "Configuring apache2"
    cp /etc/apache2/apache2.conf{,.bak}
    cat "$BASE/rc/apache2.conf" > /etc/apache2/apache2.conf
    cat "$BASE/rc/wordpress.conf" > /etc/apache2/sites-available/wordpress.conf
    cat "$BASE/rc/security.conf" > /etc/apache2/conf-available/security.conf
    cat "$BASE/rc/modsecurity.conf" > /etc/modsecurity/modsecurity.conf
    cat "$BASE/rc/crs-setup.conf" > /usr/share/modsecurity-crs/crs-setup.conf
    cat "$BASE/rc/security2.conf" > /etc/apache2/mods-available/security2.conf
	chown root:root /etc/apache2
	chmod 755 /etc/apache2
    ln -s /usr/share/wordpress /var/www/html/wordpress
    a2enconf security
    a2dissite 000-default
    a2ensite wordpress
    a2enmod rewrite security2 evasive
    a2dismod -f include imap info userdir autoindex
    mkdir -p /var/cache/modsecurity/uploads
    chmod -R 750 /var/cache/modsecurity
    ufw allow http
    ufw allow https
    # TODO: use TLS
    echo "Restarting apache2"
    systemctl reload apache2
    echo "Done"

    echo "Successfully configured Apache2"

    ready "Compare original config with new, also disable /server-status if exists"
    vim -O /etc/apache2/apache2.conf{,.bak}

    ready "Inspect config overrides"
    cd /etc/apache2/
    bash

    ready "Inspect .htaccess (located in public directory)"
    bash

    ready "Inspect sites-available and sites-enabled"
    cd /etc/apache2
    bash

    echo "Restarting apache2"
    systemctl reload apache2
    echo "Done"
}
cfg-mysql() {
    read -n1 -rp "Is MySQL a critical service? [ynI]"
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        cp -r /etc/mysql "$BACKUP"
        echo -e "[mysqld]\nbind-address = 127.0.0.1\nskip-show-database" > /etc/mysql/mysql.conf.d/mysqld.cnf
        echo -e "[mysql]\nlocal-infile=0" > /etc/mysql/conf.d/mysql.cnf
        systemctl restart mysql

        grep -rn "skip-grant-tables" /etc/mysql
        ready "remove occurrences of skip-grant-tables"
        cd /etc/mysql
        bash

        ready "Run mysql_secure_installation"
        mysql_secure_installation

        todo "add password to all users (incl. mysql & root)"
        todo "check if users have the right privileges"
        systemctl restart mysql
    elif [[ $REPLY =~ ^[Nn]$ ]]; then
        apt -my --ignore-missing purge mysql*
    else
        echo "No action taken"
    fi
}
cfg-php() {
    cat "$BASE/rc/php.ini" > /etc/php/7.0/cli/php.ini
    php --ini
    ready "Look for extra PHP configurations"
    bash
}
cfg-wordpress() {
    gzip -d /usr/share/doc/wordpress/examples/setup-mysql.gz
    bash /usr/share/doc/wordpress/examples/setup-mysql -n wordpress localhost
    chown -R www-data:www-data /var/www/
    chown -R www-data /usr/share/wordpress
    find /var/www -type d -exec chmod 775 {} \;
    find /usr/share/wordpress -type d -exec chmod 775 {} \;
    systemctl restart apache2
    todo "Go to http://localhost/wp-admin/install.php"
    todo "Secure Wordpress (go to admin panel)"
    ready "Look for insecure files in /usr/share/wordpress and /var/www/"
    bash
    ready "Try finding weird plugins"
    bash
}
cfg-bind9() {
    read -n 1 -rp "Is bind9 a critical service? [ynI] "
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        # TODO
        echo NI
        apt install -y bind9
        sed -i 's/^.*version\s+".*";.*/version none;/' /etc/bind/named.conf.options
        sed -i 's/^.*allow-transfer.*;.*/allow-transfer {none;};/' /etc/bind/named.conf.options
        echo "Note: see https://wiki.debian.org/Bind9"
        ready "Configure bind9 (/etc/bind/...)"

        cd /etc/bind/ &>/dev/null || cd /etc || true
        bash
    elif [[ $REPLY =~ ^[Nn]$ ]]; then
        disnow named
        apt -my purge bind9*
    else
        echo "Will not remove bind9"
    fi

}
cfg-nginx() {
    read -n 1 -rp "Is nginx a critical service? [ynI] "
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        # TODO
        echo NI
        apt install -y nginx
        ready "Configure nginx"
        cd /etc/nginx || cd /etc
        bash
    elif [[ $REPLY =~ ^[Nn]$ ]]; then
        disnow nginx
        apt -my purge nginx*
    else
        echo "Will not remove nginx"
    fi
}
cfg-postgresql() {
    read -n1 -rp "Is postgresql a critical service? [ynI] "
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        # TODO
        echo NI
        apt install -y postgresql{,-contrib}
        ready "Configure postgresql (/etc/postgresql/VERSION/...)"
        cd /etc/postgresql
        bash
    elif [[ $REPLY =~ ^[Nn]$ ]]; then
        disnow postgresql
        apt -my purge postgresql
    else
        echo "Will not remove postgresql"
    fi
}
cfg-samba() {
    read -n1 -rp "Is Samba a critical service? [ynI]"
    if [[ $REPLY =~ ^[Yy]$ ]]; then
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
        todo "Check admin users of share"
        echo "Note: config file is /etc/samba/smb.conf"
        todo "In [global] section add: restrict anonymous = 2"
        cat <<'EOF'
[ipc$]
hosts allow = 127.0.0.1
hosts deny = 0.0.0.0/0
guest ok = no
browseable = no
EOF
        todo "Replace ipc$ share with above"
        systemctl restart smbd.service nmbd.service

    elif [[ $REPLY =~ ^[Nn]$ ]]; then
        echo "Removing samba"
        systemctl disable --now smbd.service nmbd.service
        apt -my purge samba*
    else
        echo "No actions taken"
    fi
}
inspect-www() {
    if [ -d /var/www/html ]; then
        ready "Inspect /var/www/html"
        cd /var/www/html || true
        ls -R
        bash
        cd - || true
    else
        echo "/var/www/html not found; no inspection necessary"
    fi
}
inspect-cron() {
    ready "Check root cron"
    crontab -e
    ready "Check user cron"
    if [ -d /var/spool/cron/crontabs/ ]; then
        cd /var/spool/cron/crontabs/ || true
        bash
    elif [ -d /var/spool/cron/ ]; then
        cd /var/spool/cron/ || true
        bash
    else
        echo "No known crontabs directory found."
        bash
    fi
    if [ -f /etc/anacrontab ]; then
        ready "Inspect anacrontab"
        vim /etc/anacrontab
    fi
    if [ -d /var/spool/anacrontab ]; then
        ready "Inspect anacrontabs"
        vim /var/spool/anacrontab
    fi
    ready "Check periodic crons (e.g., /etc/cron.hourly)"
    cd /etc || true
    ls -R /etc/cron.*
    bash
    cd "$BASE" || true
}
inspect-ports() {
    ready "Inspect ports"
    echo ----
    netstat -plunte
    echo ----
    lsof -i -n -P
    echo ----
    ready "Take action in bash (check if netstat / ss is compromised)"
    bash
}
inspect-netcat() {
    if pgrep nc > /dev/null; then
        ready "View netcat backdoors"
        echo ----
        pgrep -a nc
        echo ----
        bash
    else
        echo "No netcat processes found"
    fi
    echo "Netcat inspection complete"
}

# ====================
# @rare
# ====================

inspect-apt-src() {
    if ! (find /etc/apt/sources.list.d 2>/dev/null | grep / -q); then
        ready "Inspect APT sources.list.d"
        vim /etc/apt/sources.list.d/
        echo "Updating APT sources..."
        apt update -y
        echo "Done"
    fi
}
inspect-file-attrs() {
    ready "Search for files with non-base ACL in /home, /etc, and /var"
    getfacl -Rs /home /etc /var | less

    ready "Search for files with special attributes"
    echo "---- begin"
    lsattr -R /etc 2>/dev/null | grep -v -e '--e--' | grep -v -e '/.*:$' | grep -v '^$'
    lsattr -R /home 2>/dev/null | grep -v -e '--e--' | grep -v -e '/.*:$' | grep -v '^$'
    lsattr -R /root 2>/dev/null | grep -v -e '--e--' | grep -v -e '/.*:$' | grep -v '^$'
    lsattr -R /var 2>/dev/null | grep -v -e '--e--' | grep -v -e '/.*:$' | grep -v '^$'
    echo "---- end"
    echo "Files listed above contain special file attributes"

    ready "Search for setuid files"
    echo "---- begin"
    find / -type f -perm -4000
    echo "---- end"
    ready "Take action in bash"
    bash
}
inspect-hosts() {
    ready "Inspect /etc/hosts, /etc/hosts.allow, /etc/hosts.deny"
    vim /etc/hosts
    vim /etc/hosts.allow
    vim /etc/hosts.deny
}
inspect-resolv() {
    cat <<'EOF' >/etc/systemd/resolved.conf
[Resolve]
DNS=8.8.8.8 8.8.4.4
EOF
    systemctl daemon-reload
    systemctl restart systemd-{networkd,resolved}
    echo "Done configuring DNS/resolved"
}
inspect-startup() {
    echo "--Inspect Start-up Scripts--"
    if [ -f /etc/rc.local ]; then
        ready "Inspect /etc/rc.local"
        vim /etc/rc.local
    fi
    if [ -d /etc/init.d ]; then
        ready "Inspect /etc/init.d/"
        vim /etc/init.d
    fi
    echo "Inspection complete"
}
inspect-unit-files() {
    if which systemctl &>/dev/null; then
        ready "View systemd unit files"
        systemctl list-unit-files
    fi
}
secure-fs() {
    echo "tmpfs      /dev/shm    tmpfs   defaults,noexec,nodev,nosuid   0 0" >> /etc/fstab
    umount /dev/shm && mount /dev/shm || echo "Failed to remount /dev/shm with new settings"
    ready "Inspect /etc/fstab"
    vim /etc/fstab
}
view-ps() {
    ready "View process hierarchy"
    ps axjf | less
    ready "Take action in bash"
    bash
}
suggestions() {
    todo "check executables with find / -perm /4000 2>/dev/null"
    todo "check /etc/skel and .bashrc"
    todo "check /etc/adduser.conf"
    todo "generate ssh keys"
    todo "View http://cypat.guru/index.php/Main_Page"
    todo "run https://github.com/openstack/ansible-hardening"
    todo "install scap workbench and scan the system"
    todo "run openvas"
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
    echo "--AV Scans--"
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
