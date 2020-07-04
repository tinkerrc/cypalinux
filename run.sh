#!/usr/bin/env bash
# Zhenkai Weng - Walnut HS CSC

set -euo pipefail

if [ ! "$(whoami)" = "root" ]; then
    echo Please try again with root priviliges...
    exit 1
fi

BASE="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
DATA="$HOME/.harden"
mkdir -p "$DATA"

todo () {
    # Follow the instruction; might have to leave terminal
    printf "\033[0;31mTODO:\033[0m %s\n" "$@"
    read -rp '->>'
}

ready() {
    # Wait for user to be ready
    printf "\033[0;35mREADY:\033[0m %s\n" "$@"
    read -rp '-?>'
}

# in case the script is stopped midway
# we don't have to go through everything again
# unless it is marked incomplete
run_once() {
    if [ -f "$DATA/$1" ]; then
        return
    fi
    eval "$@"
    echo
    echo "Tip: Don't forget to record scoring reports and take snapshots!"
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
    if ! python3 --version; then
        ready "Try installing python3"
        bash
    else
        echo Python3 is installed.
    fi
}

backup() {
    echo Backing up files...
    BACKUP=/backup
    mkdir -p $BACKUP
    cp -a /home $BACKUP
    cp -a /etc $BACKUP
    echo NOTE: /etc and /home are backed up into $BACKUP
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
    echo Sudoers audit complete
}

inspect_ssh_config() {
    ready "Diff sshd config"
    vim -d /etc/ssh/sshd_config "$BASE/rc/sshd_config"
    service ssh restart || true
    echo sshd config complete
}

ensure_ssh_is_running() {
    service ssh restart || true
    if ! pgrep ssh > /dev/null; then
        ready "Ensure sshd is running"
        bash
    fi
}

ensure_ssh_is_installed() {
    if ! [ -x /usr/bin/sshd ]; then
        echo Installing openssh-server
        apt install -y openssh-server > /dev/null
        service ssh start || true
        echo Installation complete
    fi
}

rm_media_files() {
    find /home -type f \( \
        -name "*.mp3" -o \
        -name "*.mov" -o \
        -name "*.mp4" -o \
        -name "*.avi" -o \
        -name "*.mpg" -o \
        -name "*.mpeg" -o \
        -name "*.flac" -o \
        -name "*.m4a" -o \
        -name "*.flv" -o \
        -name "*.ogg" -o \
        -name "*.gif" -o \
        -name "*.png" -o \
        -name "*.jpg" -o \
        -name "*.jpeg" \) > "$DATA/banned_files"
    python3 "$BASE/rmfiles.py" "$DATA/banned_files"
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
    ufw reject telnet
    echo Allows outgoing traffic by default
    echo Denies incoming traffic by default
    echo "Allow   :  SSH"
    echo "Reject  :  Telnet"
    ready "Further modify UFW settings according to README (e.g., ufw allow 80)"
    bash
}

inspect_svc() {
    echo "Inspect services"
    echo " [+] : running"
    echo " [-] : stopped"
    echo " [?] : upstart service / status unsupported"
    ready "Press [ENTER] to get list of services"
    service --status-all | sort
    ready "Inspect"
    bash
}

config_sysctl() {
    cat "$BASE/rc/sysctl.conf" > /etc/sysctl.conf
    sysctl -e -p /etc/sysctl.conf
    echo /etc/sysctl.conf has been installed
}

config_common() {
    apt install -y libpam-cracklib
    cat "$BASE/rc/common-password" > /etc/pam.d/common-password
    cat "$BASE/rc/common-auth" > /etc/pam.d/common-auth
    cat "$BASE/rc/login.defs" > /etc/login.defs
    cat "$BASE/rc/host.conf" > /etc/host.conf
    echo PAM config, login.defs, and host.conf have been installed
}

audit_pkgs() {
    read -rp "Should apache2 be removed? [y/N] "
    if [[ $REPLY = "y" ]]; then
        echo "Removing apache2..."
        apt-get -my purge apache2 &> /dev/null
    else
        echo "Will not remove apache2."
    fi

    read -rp "Should samba be removed? [y/N] "
    if [[ $REPLY = "y" ]]; then
        echo "Removing samba..."
        apt-get -my purge samba* &> /dev/null
    else
        echo "Will not remove samba."
    fi

    read -rp "Should vsftpd and openssh-sftp-server be removed? [y/N] "
    if [[ $REPLY = "y" ]]; then
        echo "Removing vsftpd..."
        apt-get -my purge vsftpd openssh-sftp-server &> /dev/null
    else
        echo "Will not remove vsftpd/openssh-sftp-server."
    fi

    ready "Press [ENTER] to remove: hydra nmap zenmap john ftp telnet bind9 medusa vino ncat netcat* ophcrack"
    echo "Removing in 5s"
    sleep 5
    apt -my purge hydra nmap zenmap john ftp telnet bind9 medusa vino ncat netcat* ophcrack > /dev/null
    ready "Look for any disallowed or unnecessary package (e.g., mysql postgresql nginx php)"
    bash
    echo "Installing additional packages..."
    apt install apparmor apparmor-profiles clamav rkhunter chkrootkit
    read -rp "Run apt upgrade?"
    if [[ $REPLY = "y" ]]; then
        apt update -y
        apt upgrade -y
        apt autoremove -y
    fi
}

inspect_ports() {
    ready "Inspect ports"
    netstat -plnt
    ready "Inspect"
    bash
}

inspect_cron() {
    ready "Check root cron"
    crontab -e
    ready "Check user cron"
    if [[ -d /var/spool/cron/crontabs/ ]]; then
        cd /var/spool/cron/crontabs/
        bash
    elif [[ -d /var/spool/cron/ ]]; then
        cd /var/spool/cron/
        bash
    else
        echo No known crontabs directory found.
        bash
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
    chmod 700 /boot

    chown root:root /etc/anacrontab
    chmod 640 /etc/anacrontab
    chown root:root /etc/crontab
    chmod 640 /etc/crontab
    chown root:root /etc/cron.hourly
    chmod 640 /etc/cron.hourly
    chown root:root /etc/cron.daily
    chmod 640 /etc/cron.daily
    chown root:root /etc/cron.weekly
    chmod 640 /etc/cron.weekly
    chown root:root /etc/cron.monthly
    chmod 640 /etc/cron.monthly
    chown root:root /etc/cron.d
    chmod 640 /etc/cron.d
    echo Common system file permissions corrected

    ready "Inspect /home and /home/* owners and permissions"
    bash
    echo "Inspection complete"
}

run_lynis() {
    cd "$DATA"
    if ! [[ -d $DATA/lynis ]]; then
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
    ready "Inspect /etc/hosts"
    vim /etc/hosts
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
    (umount /dev/shm && mount /dev/shm) || echo Failed to remount /dev/shm with new settings
    ready "Inspect /etc/fstab"
    vim /etc/fstab
}

config_fail2ban() {
    apt install -y fail2ban
    touch /etc/fail2ban/jail.local
    cat "$BASE/rc/jail.local" > jail.local
    service fail2ban restart
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

harden() {
    echo Walnut High School CSC CyberPatriot Linux Hardening Script
    if ! [ -d "$BASE/rc" ]; then
        echo The resources directory is missing
        exit 1
    fi

    todo "Launch a root shell in another terminal in case something goes wrong"
    run_once inspect_apt_src
    echo Updating package lists...
    apt update
    clear

    # Preliminaries
    run_once ensure_ssh_is_installed
    ensure_ssh_is_running
    run_once backup
    run_once ensure_python3

    # Get started
    run_once readme
    run_once do_fq

    # User auditing
    run_once lock_root
    run_once chsh_root
    run_once remove_unauth_users
    run_once inspect_passwd
    run_once inspect_group
    run_once inspect_sudoer

    # Service config
    ensure_ssh_is_running
    run_once inspect_ssh_config
    ensure_ssh_is_running
    run_once config_php

    # Disallowed files
    run_once rm_media_files
    run_once find_pw_text_files

    # Software auditing
    run_once config_unattended_upgrades
    run_once audit_pkgs

    # Miscellaneous
    run_once inspect_hosts
    run_once lightdm_disable_guest
    run_once fix_file_perms
    run_once firewall
    run_once config_sysctl
    run_once config_common
    run_once secure_fs
    run_once config_fail2ban
    run_once inspect_startup

    # Abnormality
    run_once inspect_svc
    run_once inspect_ports
    run_once inspect_cron
    run_once inspect_netcat

    # Scan
    run_once run_lynis
    run_once run_linenum

    # Last-minute suggestions
    ensure_ssh_is_running
    run_once suggestions
    echo Done!
}

harden

# keep a root shell in case something goes wrong
echo A root shell for your convenience
bash
