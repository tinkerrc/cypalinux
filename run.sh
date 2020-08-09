#!/usr/bin/env bash
# Zhenkai Weng - Walnut HS CSC

set -euo pipefail

if [ ! "$(whoami)" = "root" ]; then
    echo Please try again with root priviliges...
    exit 1
fi

BASE="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
DATA="$HOME/.harden"
BACKUP=/backup
mkdir -p "$DATA"

todo () {
    # Follow the instruction; might have to leave terminal
    echo -e "\033[0;31mTODO:\033[0m $*"
    read -n 1 -rp "Press [ENTER] when you finish"
}

ready() {
    # Wait for user to be ready
    echo -e "\033[0;35mREADY:\033[0m $*"
    read -n 1 -rp "Press [ENTER] when you are ready"
}

do_task() {
    # in case the script is stopped midway
    # we don't have to go through everything again
    # unless it is not marked complete
    if [ -f "$DATA/$1" ]; then
        return
    fi
    eval "$@"
    echo
    echo "Tip: Don't forget to record scoring reports and take notes!"
    read -p "Mark this task as finished? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        touch "$DATA/$1"
    fi
    clear
}

# tasks

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
    cp -a /home "$BACKUP"
    cp -a /etc "$BACKUP"
    cp -a /var "$BACKUP"
    if [ -d "$BACKUP" ]; then
        echo NOTE: /etc /var and /home are backed up into $BACKUP
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

inspect_sudoer() {
    ready "Press [ENTER] to launch visudo"
    visudo
    if [ -d /etc/sudoers.d ]; then
        ready "View all overrides"
        cd /etc/sudoers.d
        bash
        cd "$BASE"
    fi
    echo Sudoers audit complete
}

restart_sshd() {
    systemctl restart sshd || service ssh restart || echo "Failed to restart sshd"
}
inspect_ssh_config() {
    ready "Diff sshd config"
    vim -d /etc/ssh/sshd_config "$BASE/rc/sshd_config"
    echo Validating...
    echo Restarting service
    restart_sshd
    echo sshd config complete
}

ensure_ssh_is_running() {
    restart_sshd
    if ! pgrep sshd > /dev/null; then
        ready "Ensure sshd is running"
        bash
    fi
}

ensure_ssh_is_installed() {
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
    ready "You might want to look for additional media files"
    bash
}

find_pw_text_files() {
    ready "Try to find, backup, and remove suspicious files (e.g., cd /home; grep -rwni P@a5w0rD)"
    bash
}

lightdm_disable_guest() {
    echo "" > "$DATA/lightdmconf" # clear file
    while read -r line
    do
        if [[ ! $line =~ ^allow-guest=[a-z]+ ]];
        then
            echo "$line" >> "$DATA/lightdmconf"
        fi
    done < /etc/lightdm/lightdm.conf
    echo "allow-guest=false" >> "$DATA/lightdmconf"

    cat "$DATA/lightdmconf" > /etc/lightdm/lightdm.conf
    cat "$DATA/lightdmconf" > /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf
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
    echo " [+] : running"
    echo " [-] : stopped"
    echo " [?] : upstart service / status unsupported"
    ready "Press [ENTER] to get list of services"
    systemctl || service --status-all | sort || echo "Failed to list services"
    ready "Inspect"
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
        apt-get -my purge apache2 &> /dev/null
    else
        echo "Will not remove apache2."
    fi

    read -rp "Remove samba? [y/N] "
    if [[ $REPLY = "y" ]]; then
        echo "Removing samba..."
        apt-get -my purge samba* &> /dev/null
    else
        echo "Will not remove samba."
    fi

    read -rp "Remove vsftpd and openssh-sftp-server? [y/N] "
    if [[ $REPLY = "y" ]]; then
        echo "Removing vsftpd..."
        apt-get -my purge vsftpd openssh-sftp-server &> /dev/null
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
    ready "Inspect"
    # TODO: make sure netstat is not compromised, otherwise install nmap
    bash
}

inspect_cron() {
    ready "Check root cron"
    crontab -e
    ready "Check user cron"
    if [ -d /var/spool/cron/crontabs/ ]; then
        cd /var/spool/cron/crontabs/
        bash
    elif [ -d /var/spool/cron/ ]; then
        cd /var/spool/cron/
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
    cd /etc
    bash
    cd "$BASE"
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

run_lynis() {
    cd "$DATA"
    if ! [[ -d "$DATA/lynis" ]]; then
        git clone --depth 1 https://github.com/CISOfy/lynis
    fi
    cd lynis
    clear
    ready 'Start lynis'
    ./lynis audit system
    ready "Inspect; run lynis scans under other modes if necessary"
    bash
}

run_linenum() {
    cd "$DATA"
    if ! [[ -d $DATA/LinEnum ]]; then
       git clone https://github.com/rebootuser/LinEnum
    fi
    cd LinEnum
    chmod u+x ./LinEnum.sh
    ./LinEnum.sh -t -e "$DATA" -r enum
    cat enum
    ready "Inspect"
    bash
}

suggestions() {
    todo "note: chage -d 0 to force reset password on next login"
    todo "consider adding a warning banner in /etc/issue.net (then add 'Banner issue.net' to sshd_config)"
    todo "in gdm3 greeter defaults config, disable-user-list=true"
    todo "apache2 - add ModEvasive and ModSecurity modules"
    todo "check executables with find / -perm /4000 2>/dev/null"
    todo "Install antimalware/rootkit programs; chkrootkit / rkhunter / clamav (freshclam)"
    todo "ensure ufw allows critical servers"
    todo "check sticky bit perm"
    todo "set apt settings see phone picture"
    todo "add a grub password, check signature"
    todo "secure fstab"
    todo "use chage if necessary"
    todo "PAM module backdoor?"
    todo "setup auditd?"
    todo "malicious kernel modules?"
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

inspect_resolv() {
    ready "Inspect /etc/resolv.conf; use 8.8.8.8 for nameserver"
    # TODO: disable systemd dns
    vim /etc/resolv.conf
    echo Done
}

av_scan() {
    echo --AV Scans--
    ready "Start chkrootkit scan"
    chkrootkit

    ready "Start rkhunter scan"
    rkhunter --update
    rkhunter --propupd
    rkhunter -c --enable all --disable none

    ready "Start ClamAV scan"
    freshclam --stdout
    clamscan -r -i --stdout --exclude-dir="^/sys" /
}

run_linpeas() {
    cd "$DATA"
    git clone --depth 1 https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/
    ready "Run linpeas.sh"
    ./privilege-escalation-awesome-scripts-suite/linPEAS/linpeas.sh
    ready "Inspect"
    bash
    cd -
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
       cd /var/www/html
       bash
       cd -
    else
        echo "/var/www/html not found; no inspection necessary"
    fi
}

inspect_acl() {
    ready "Search for files with non-base ACL in /home, /etc, and /var"
    getfacl -Rs /home /etc /var
    ready "Inspect"
    bash
}

inspect_unit_files() {
    if which systemctl &>/dev/null; then
        ready "View systemd unit files"
        systemctl list-unit-files
    fi
}

harden() {
    # TODO: prepend vim-editing with chmod if necessary

    # TODO: look for special ACLs (getfacl --skip-base; then reset by setfacl -b $FILE) and special attributes
    # TODO: ps axjf # view process hierarchy
    # TODO: check systemd unit files in /etc/systemd/{system,user} and ~/.config/systemd/*
    # TODO: externalize (move into separate shell script) stuff like run_linpeas, av_scan etc
    # TODO: disable login manager root & guest login for lightdm & gdm
    # TODO: look for wordlists, check /opt
    # TODO: add Eric's malware section to script

    echo "Walnut High School CSC CyberPatriot Linux Hardening Script"
    echo " - Data directory: $DATA"
    echo " - Base directory: $BASE"
    if ! [ -d "$BASE/rc" ]; then
        echo "The resources directory is missing"
        exit 1
    fi

    todo "Don't forget to use 'script' to record the output"
    todo "Launch a root shell in another terminal in case something goes wrong"

    do_task inspect_apt_src
    echo Updating package lists...
    apt update
    clear

    # Preliminaries
    do_task ensure_vim
    do_task ensure_ssh_is_installed
    ensure_ssh_is_running
    do_task backup
    do_task ensure_python3

    # Get started
    do_task readme
    do_task do_fq

    # User auditing
    do_task lock_root
    do_task chsh_root
    do_task remove_unauth_users
    do_task inspect_passwd
    do_task inspect_group
    do_task inspect_sudoer
    do_task lightdm_disable_guest

    # Service config
    do_task config_apache
    ensure_ssh_is_running
    do_task inspect_ssh_config
    ensure_ssh_is_running
    do_task config_php
    do_task inspect_www

    # Disallowed files
    do_task rm_media_files
    do_task find_pw_text_files

    # Software auditing
    do_task config_unattended_upgrades
    do_task audit_pkgs

    # Miscellaneous
    do_task inspect_resolv
    do_task restrict_cron
    do_task inspect_hosts
    do_task fix_file_perms
    do_task firewall
    do_task config_sysctl
    do_task config_common
    do_task secure_fs
    do_task config_fail2ban
    do_task inspect_startup
    do_task inspect_acl

    # Abnormality
    do_task inspect_svc
    do_task inspect_ports
    do_task inspect_cron
    do_task inspect_netcat

    # Scan
    do_task run_lynis
    do_task run_linenum
    do_task run_linpeas

    # Last-minute suggestions
    ensure_ssh_is_running
    do_task suggestions
    do_task av_scan
    echo Done!
}


harden

# keep a root shell in case something goes wrong
echo A root shell for your convenience
bash
