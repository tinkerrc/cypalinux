#!/usr/bin/env bash
if [[ $_ != "$0" ]]; then
    echo "Invoke harden to secure the machine"
else
    echo "Run 'source harden.sh' instead"
    exit 1
fi

# Export all functions
set -a

# shellcheck source=./common.sh
source "$(dirname "$0")/common.sh"

# ===================================
# CyPa Hardening Script (Team 1)
# Walnut HS Cyber Security Club
# ===================================

harden() {
    script -ac harden_impl "$DATA/log"
}

harden_impl() {
    echo "Walnut High School CSC CyberPatriot Linux Hardening Script"
    echo " => Current time   : $(date '+%Y-%m-%d %H:%M:%S %Z')"
    echo " => Data directory : $DATA"
    echo " => Base directory : $BASE"
    echo " => Output file    : $DATA/log"

    section_preliminaries
    section_get_started
    section_user_audit
    section_svc_config
    section_disallowed
    section_common_config
    section_rare_vulns

    restart_sshd
    todo "Run scan.sh in a new terminal window"
    do_task suggestions
    echo Done!

    # keep a root shell in case something goes wrong
    echo Here is a root shell for your convenience
    bash
}

section_preliminaries() {
    mkdir -p "$DATA"
    setxkbmap -option caps:swapescape

    if ! [ -d "$BASE/rc" ]; then
        echo "The resources directory is missing"
        exit 1
    fi

    if [ ! "$(whoami)" = "root" ]; then
        echo Please try again with root priviliges...
        exit 1
    fi

    todo "Don't forget to use 'script' to record the output"
    todo "Launch a root shell in another terminal in case something goes wrong"

    do_task ensure_vim
    do_task inspect_apt_src
    do_task install_ssh
    do_task backup
    do_task ensure_python3
}

section_get_started() {
    do_task readme
    do_task do_fq
}

section_user_audit() {
    do_task lock_root
    do_task chsh_root
    do_task remove_unauth_users
    do_task inspect_passwd
    do_task inspect_group
    do_task config_sudoer
    do_task config_dm
}

section_svc_config() {
    do_task inspect_svc
    do_task inspect_cron
    do_task config_sshd
    do_task config_apache
    do_task config_ftp
    do_task config_php
    do_task inspect_www
    do_task view_ps
}

section_disallowed() {
    do_task rm_media_files
    do_task find_pw_text_files
    do_task inspect_ports
    do_task inspect_netcat
}

section_common_config() {
    do_task config_unattended_upgrades
    do_task audit_pkgs
    do_task inspect_hosts
    do_task config_sysctl
    do_task fix_file_perms
    do_task firewall
    do_task restrict_cron
    do_task config_common
    do_task inspect_startup
}

section_rare_vulns() {
    do_task secure_fs
    do_task inspect_resolv
    do_task config_fail2ban
    do_task inspect_file_attrs
}

# ====================
# Tasks
# ====================

do_fq() {
    todo "Do forensic questions"
}

readme() {
    todo "Read README file"
}

ensure_python3() {
    echo Checking python3 installation...
    if ! (python3 --version >/dev/null); then
        ready "Try installing python3"
        bash
    else
        echo Python3 is installed.
    fi
}

backup() {
    echo Backing up files...
    mkdir "$BACKUP"
    cp -a /home "$BACKUP" || true
    cp -a /etc "$BACKUP" || true
    cp -a /var "$BACKUP" || true
    if [ -d "$BACKUP" ]; then
        echo "NOTE: /etc /var and /home are backed up into $BACKUP"
    else
        echo "Backup failed; $BACKUP not found"
    fi
}

lock_root() {
    read -p "Lock the root account? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        passwd -l root
        echo root account locked
    else
        echo root account not locked
    fi
}

chsh_root() {
    read -p "Change root shell to /usr/sbin/nologin? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo root shell => nologin
        chsh -s /usr/sbin/nologin root
    else
        echo root shell not changed
    fi
}

remove_unauth_users() {
    ready "Enter a list of authorized users"
    vim "$DATA/auth"
    awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd > "$DATA/unchecked"
    echo Please enter a new password for all users
    pass=$(openssl passwd -1)
    python3 "$BASE/rmusers.py" "$DATA/auth" "$DATA/unchecked" "$DATA/unauthed" "$pass"
    echo User audit complete
}

inspect_passwd() {
    grep :0: /etc/passwd
    ready "Inspect abnormal users (eg. UID 0, weird shell/home)"
    vim /etc/passwd
    echo /etc/passwd inspection complete
}

inspect_group() {
    grep adm /etc/group
    grep sudo /etc/group
    ready "Inspect groups"
    vim /etc/group
    echo /etc/group inspection complete
}

config_sudoer() {
    ready "Press [ENTER] to launch visudo"
    visudo
    if [ -d /etc/sudoers.d ]; then
        tail -n +1 /etc/sudoers.d/*
        ready "Take action in bash"
        cd /etc/sudoers.d || true
        bash
        cd "$BASE" || true
    fi
    echo Sudoers audit complete
}

restart_sshd() {
    echo Restarting sshd
    if ! (systemctl restart sshd || service ssh restart); then
        echo "Failed to restart sshd"
        ready "Ensure sshd is running"
        bash
    else
        echo "Successfully restarted sshd"
    fi
}

config_sshd() {
    ready "Diff sshd config"
    vim -d /etc/ssh/sshd_config "$BASE/rc/sshd_config"
    restart_sshd
    echo sshd config complete
}

install_ssh() {
    if ! [ -x /usr/bin/sshd ]; then
        echo Installing openssh-server
        apt install -y openssh-server > /dev/null
        restart_sshd
        echo Installation complete
    fi
}

rm_media_files() {
    if ! which &>/dev/null; then
        apt install -y mlocate findutils
    fi
    ready "Inspect locate config; look for excluded paths and extensions"
    vim /etc/updatedb.conf
    echo "Updating database"
    updatedb

    if ! [ -d "$BACKUP/home" ]; then
        echo "Warning: backup for home not found"
        ready -n 1 -rp "Press [ENTER] to continue"
    fi
    locate -0 -i --regex \
        "\.(aac|avi|flac|flv|gif|jpeg|jpg|m4a|mkv|mov|mp3|mp4|mpeg|mpg|ogg|png|rmvb|wma|wmv)$" | \
        xargs -0 -t rm | tee "$DATA/banned_files" || echo "Couldn't remove files"
    echo "The above files are deleted. The file names are stored in $DATA/banned_files"
    ready "You might want to look for additional media files and other disallowed files. Check /opt for example"
    bash
}

find_pw_text_files() {
    ready "Try to find, backup, and remove suspicious files (e.g., cd /home; grep -rwni P@a5w0rD)"
    bash
}

config_dm() {
    echo "" > "$DATA/lightdmconf" # clear file
    while read -r line
    do
        if [[ ! $line =~ ^allow-guest=[a-z]+ ]];
        then
            echo "$line" >> "$DATA/lightdmconf"
        fi
    done < /etc/lightdm/lightdm.conf
    {
        echo "allow-guest=false"
        echo "greeter-hide-users=true"
        echo "greeter-show-manual-login=true"
    } >> "$DATA/lightdmconf"
    cat "$DATA/lightdmconf" > /etc/lightdm/lightdm.conf
    cat "$DATA/lightdmconf" > /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf

    echo "Ubuntu 14: /etc/lightdm/"
    echo "Ubuntu 16: /usr/share/lightdm/lightdm.conf.d/"
    echo "Debian (GDM): /etc/gdm/gdm.conf"
    ready "Inspect DM config"
    bash
}

config_unattended_upgrades() {
    apt install -y unattended-upgrades
    dir=/etc/apt/apt.conf.d
    mkdir -p "$dir" # should already be ther
    file_pdc="10periodic"
    file_uud="50unattended-upgrades"
    cat "$BASE/rc/$file_pdc" > "$dir/$file_pdc"
    cat "$BASE/rc/$file_uud" > "$dir/$file_uud"
    echo Unattended upgrades config installed
}

inspect_apt_src() {
    ready "Inspect apt sources"
    vim /etc/apt/sources.list
    vim /etc/apt/sources.list.d/
}

firewall() {
    read -p "Mark this task as finished? [Y/n] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        touch "$DATA/$1"
    fi
    apt install -y ufw iptables
    ufw enable
    ufw allow ssh
    ufw default deny incoming
    ufw default allow outgoing
    ufw deny telnet
    ufw deny 2049
    ufw deny 515
    ufw deny 111
    ufw logging high
    echo Allows outgoing traffic by default
    echo Denies incoming traffic by default
    echo "Allow   :  SSH"
    echo "Reject  :  Telnet"
    ufw status verbose
    if [ -f /etc/ufw/sysctl.conf ]; then
        ready "Inspect UFW override config"
        vim /etc/ufw/sysctl.conf
    fi
    ready "Further modify UFW settings according to README (e.g., ufw allow 80)"
    bash
}

inspect_svc() {
    echo "Inspect services"
    if ! which service &>/dev/null; then
        echo " [+] : running"
        echo " [-] : stopped"
        echo " [?] : upstart service / status unsupported"
    fi
    ready "Press [ENTER] to get list of services"
    systemctl || service --status-all | sort || echo "Failed to list services"
    ready "Inspect services and systemd units in /etc/systemd and /home/**/.config/systemd"
    bash
}

config_sysctl() {
    cat "$BASE/rc/sysctl.conf" > /etc/sysctl.conf
    sysctl -e -p /etc/sysctl.conf
    if [ -d /etc/sysctl.d ]; then
        ready "Inspect sysctl.d"
        vim /etc/sysctl.d
    fi
    echo /etc/sysctl.conf has been installed
}

config_common() {
    apt install -y libpam-cracklib
    cat "$BASE/rc/common-password" > /etc/pam.d/common-password
    cat "$BASE/rc/common-auth" > /etc/pam.d/common-auth
    cat "$BASE/rc/common-account" > /etc/pam.d/common-account
    cat "$BASE/rc/common-session" > /etc/pam.d/common-session
    cat "$BASE/rc/login.defs" > /etc/login.defs
    cat "$BASE/rc/host.conf" > /etc/host.conf
    echo PAM config, login.defs, and host.conf have been installed
}

audit_pkgs() {
    read -rp "Remove apache2? [y/N] "
    if [[ $REPLY = "y" ]]; then
        echo "Removing apache2..."
        apt -my purge apache2 &> /dev/null
    else
        echo "Will not remove apache2."
    fi

    read -rp "Remove samba? [y/N] "
    if [[ $REPLY = "y" ]]; then
        echo "Removing samba..."
        apt -my purge samba* &> /dev/null
    else
        echo "Will not remove samba."
    fi

    read -rp "Remove vsftpd and openssh-sftp-server? [y/N] "
    if [[ $REPLY = "y" ]]; then
        echo "Removing vsftpd..."
        apt -my purge vsftpd openssh-sftp-server &> /dev/null
    else
        echo "Will not remove vsftpd/openssh-sftp-server."
    fi

    ready "Press [ENTER] to remove: hydra nmap zenmap john ftp telnet bind9 medusa vino ncat netcat* ophcrack fcrackzip hashcat"
    echo "Removing in 5s"
    sleep 5
    apt -my purge hydra nmap zenmap john ftp telnet bind9 medusa vino netcat* ophcrack minetest aircrack-ng hashcat fcrackzip > /dev/null
    ready "Look for any disallowed or unnecessary package (e.g., mysql postgresql nginx php)"
    bash
    echo "Installing additional packages..."
    apt install apparmor apparmor-profiles clamav rkhunter chkrootkit
    read -rp "Run apt upgrade?"
    if [[ $REPLY = "y" ]]; then
        apt update -y
        apt dist-upgrade -y
        apt autoremove -y
    fi
}

inspect_ports() {
    ready "Inspect ports"
    echo ----
    netstat -plunte
    echo ----
    lsof -i -n -P
    echo ----
    ready "Take action in bash"
    # TODO: make sure netstat is not compromised, otherwise install nmap
    bash
}

inspect_cron() {
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
        echo No known crontabs directory found.
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
    bash
    cd "$BASE" || true
}

fix_file_perms() {
    chmod 644 /etc/passwd
    chown root:root /etc/passwd
    chmod 644 /etc/group
    chown root:root /etc/group
    chmod 600 /etc/shadow
    chown root:root /etc/shadow
    chmod 600 /etc/gshadow
    chown root:root /etc/gshadow
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
    echo Common system file permissions corrected

    chmod 755 /home
    chmod 700 /home/*
    find /home -maxdepth 2 -mindepth 2 -name ".ssh" -type d -exec chmod 700 {} \; -print
    # assuming there's no funny business going on in .ssh/, should only have files
    # not directories
    find /home -maxdepth 3 -mindepth 2 -path "*.ssh*" -type f -exec chmod 600 {} \; -print
    echo "Secured home and .ssh/* permissions"

    ready "Inspect /home and /home/* owners and permissions"
    bash
    echo "Inspection complete"
}

suggestions() {
    todo "note: chage -d 0 to force reset password on next login"
    todo "consider adding a warning banner in /etc/issue.net (then add 'Banner issue.net' to sshd_config)"
    todo "in gdm3 greeter defaults config, disable-user-list=true"
    todo "apache2 - add ModEvasive and ModSecurity modules"
    todo "check executables with find / -perm /4000 2>/dev/null"
    todo "set apt settings see phone picture"
    todo "setup auditd?"
    todo "malicious aliases?"
    todo "check /etc/skel"
    todo "check /etc/adduser.conf"
    todo "generate ssh key"
    todo "install scap workbench and scan the system"
    todo "run openvas"
    todo "run https://github.com/openstack/ansible-hardening"
}

inspect_hosts() {
    ready "Inspect /etc/hosts, /etc/hosts.allow, /etc/hosts.deny"
    vim /etc/hosts
    vim /etc/hosts.allow
    vim /etc/hosts.deny
}

inspect_netcat() {
    if pgrep nc > /dev/null; then
        ready "View netcat backdoors"
        echo ----
        pgrep -a nc
        echo ----
        bash
    else
        echo 'No netcat processes found'
    fi
    echo 'Netcat inspection complete'
}

secure_fs() {
    echo "tmpfs      /dev/shm    tmpfs   defaults,noexec,nodev,nosuid   0 0" >> /etc/fstab
    umount /dev/shm && mount /dev/shm || echo Failed to remount /dev/shm with new settings
    ready "Inspect /etc/fstab"
    vim /etc/fstab
}

config_fail2ban() {
    apt install -y fail2ban
    touch /etc/fail2ban/jail.local
    cat "$BASE/rc/jail.local" > jail.local
    systemctl restart fail2ban || service fail2ban restart || echo "Failed to restart fail2ban"
}

config_php() {
    echo --PHP configuration--
    if php --version >/dev/null; then
        read -rp "Enter php config location (hint: php --ini): " PHPCONF
        ready "Inspect PHP config (original | suggested)"
        vim -O "$PHPCONF" "$BASE/rc/php.ini"
    else
        echo "PHP not found. No actions necessary."
    fi
}

inspect_startup() {
    echo --Inspect Start-up Scripts--
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

restrict_cron() {
    echo 'Setting allowed cron/at users to root'
    crontab -r # reset crontabs
    # only root can use cron & at
    echo root > /etc/cron.allow
    echo root > /etc/at.allow
    chmod 644 /etc/{cron,at}.allow
    echo Done!
}

config_apache() {
    echo 'Securing apache2 config'
    if [ -f /etc/apache2/apache2.conf ]; then
        {
            echo "<Directory />"
            echo "        AllowOverride None"
            echo "        Order Deny,Allow"
            echo "        Deny from all"
            echo "</Directory>"
            echo "UserDir disabled root"
        } >> /etc/apache2/apache2.conf
        echo "Success."

        ready "Inspect config"
        vim /etc/apache2/apache2.conf

        echo Restarting apache2
        systemctl restart apache2 || service apache2 restart || echo "Failed to restart Apache2"
    else
        echo "No apache2 config found"
    fi
    echo Done
}

config_ftp() {
    read -n 1 -rp "Is Pure-FTPD a critical service? [Y/n]"
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        echo "Removing Pure-FTPD"
        apt autoremove --purge pure-ftpd
    else
        echo "Installing Pure-FTPD"
        apt install pure-ftpd

        cp -r /etc/pure-ftpd/conf /etc/pure-ftpd/conf.bak
        # TODO: Figure out TLSCipherSuite vs TLS?
        # TODO: Confirm all of these
        echo "2" > /etc/pure-ftpd/conf/TLS
        echo "no" > /etc/pure-ftpd/conf/NoAnonymous
        echo "no" > /etc/pure-ftpd/conf/AnonymousOnly
        echo "no" > /etc/pure-ftpd/conf/UnixAuthentication
        echo "yes" > /etc/pure-ftpd/conf/PAMAuthentication
        # TODO: Figure out ChrootEveryone

        # TODO: Finish below
        #mkdir /etc/ssl/private
        #sudo openssl req -x509 -nodes -days 7300 -newkey rsa:2048 -keyout /etc/ssl/private/pure-ftpd.pem -out /etc/ssl/private/pure-ftpd.pem

        #chmod 600 /etc/ssl/private/pure-ftpd.pem

        systemctl restart pure-ftpd
    fi

    read -n 1 -rp "Is VSFTPD a critical service? [Y/n]"
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        echo "Removing VSFTPD"
        apt autoremove --purge vsftpd
    else
        apt install vsftpd

        cp /etc/vsftpd.conf /etc/vsftpd.conf.bak
        # TODO: confirm all of these
        sed -i "s/anonymous_enable=.*/anonymous_enable=NO/" /etc/vsftpd.conf
        sed -i "s/#chroot_local_user=.*/chroot_local_user=YES/" /etc/vsftpd.conf
        sed -i "s/local_enable=.*/local_enable=YES/" /etc/vsftpd.conf
        sed -i "s/#write_enable=.*/write_enable=YES/" /etc/vsftpd.conf
        sed -i "s/ssl_enable=.*/ssl_enable=YES/" /etc/vsftpd.conf

        # TODO: finish below
        #mkdir /etc/ssl/private
        #openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/vsftpd.key -out /etc/ssl/certs/vsftpd.crt

        #chmod 600 /etc/ssl/private/vsftpd.key

        systemctl restart vsftpd
    fi

    read -n 1 -rp "Is Pro-FTPD a critical service? [Y/n]"
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        echo "Removing Pro-FTPD"
        apt autoremove --purge proftpd
    else
        apt install proftpd

        cp /etc/proftpd/proftpd.conf /etc/proftpd/protftpd.conf.bak
        # TODO: confirm all of these
        sed -i "s/# DefaultRoot\t\t\t~/DefaultRoot\t\t\ton/" /etc/proftpd/proftpd.conf
        sed -i "s/# RequireValidShell\t\toff/RequireValidShell\t\t\ton/" /etc/proftpd/proftpd.conf
        sed -i "s/# AuthOrder\t\t\t.*/AuthOrder\t\t\ton/" /etc/proftpd/proftpd.conf
        # TODO: finish below
        #mkdir /etc/ssl/private
        #openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/vsftpd.key -out /etc/ssl/certs/vsftpd.crt

        #chmod 600 /etc/ssl/private/vsftpd.key
        systemctl restart proftpd
    fi
}

inspect_resolv() {
    ready "Inspect /etc/resolv.conf; use 8.8.8.8 for nameserver"
    # TODO: disable systemd dns
    vim /etc/resolv.conf
    echo Done
}

ensure_vim() {
    if ! which vim &>/dev/null; then
        apt install -y vim
        echo "Installed vim"
    else
        echo "Vim is already installed"
    fi
    # TODO: Add a sane default config
    # TODO: inspect config?
}

inspect_www() {
    if [ -d /var/www/html ]; then
        ready "Inspect /var/www/html"
        cd /var/www/html || true
        bash
        cd - || true
    else
        echo "/var/www/html not found; no inspection necessary"
    fi
}

inspect_file_attrs() {
    ready "Search for files with non-base ACL in /home, /etc, and /var"
    getfacl -Rs /home /etc /var
    ready "Take action in bash"
    bash
    ready "Search for files with special attributes"
    lsattr -R /etc | grep -v -e '--------------e-----'
    lsattr -R /home | grep -v -e '--------------e-----'
    lsattr -R /root | grep -v -e '--------------e-----'
    lsattr -R /var | grep -v -e '--------------e-----'
    ready "Take action in bash"
    bash
}

inspect_unit_files() {
    if which systemctl &>/dev/null; then
        ready "View systemd unit files"
        systemctl list-unit-files
    fi
}

view_ps() {
    ready "View process hierarchy"
    ps axjf
    ready "Take action in bash"
    bash
}
