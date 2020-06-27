#!/bin/bash
# CyberPatriot Semifinals round Linux Script
# Walnut CSC
# Zhenkai Weng

pass="WRhSzWm/eylpE" # "CyPaPaWd1920!@#"
BASE="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
ID=$(date +"%H%M")
BACKUP=$BASE/backup/$ID/
mkdir -p "$BACKUP"
mkdir -p "$BASE"/reports

todo () {
    # Leave the terminal window, following the instruction
    printf "\033[0;31mTODO:\033[0m %s\n" "$@"
    read -rp '->>'
}
ready() {
    # Basically: Are you ready?
    printf "\033[0;35mREADY:\033[0m %s\n" "$@"
    read -rp '-?>'
}
backup() {
    printf "Backing up %s\n" "$1"
    cp -a "$1" "$BACKUP"
}
section () {
    echo ''
    echo "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-"
    echo 'Wait for Scoring Report to update...'
    todo "Record the scoring report"
    #vim $BASE/reports/$(date +"%H:%M:%S")
    clear
    for i in $BASE/reports/*
    do
        echo "$i: " $(wc -l $i) "vulns"
    done
    clear
    printf " ===== %s ===== " "$1"
    read -rp '>>'
}

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
echo " ===== Introduction ===== "
echo Walnut CSC Linux Hardening for CyberPaatriot
echo "** Requires root Permissions **"
if [ ! $(whoami) = "root" ];
then
    echo "Please try again with root priviliges..."
    exit 1
fi
todo "check if vim exists"
echo "Backing up files"
backup /etc
todo "Read README thoroughly"
todo "Do Forensic Questions..."

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
section "User Auditing"
echo "Locking root account"
passwd -l root > /dev/null
#usermod --expiredate 1 root > /dev/null
ready "Enter allowed user in vim after [ENTER] ...\nNote: Don't put the auto-login account in there!"
vim $BASE/auth-users
sort $BASE/auth-users > $BASE/auth-users
IFS=$'\r\n' GLOBIGNORE='*' command eval  'AUTH_USERS=($(cat $BASE/auth-users))'
mapfile -t UNCHECKED_USERS < <(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd )
for usr in "${UNCHECKED_USERS[@]}"
do
    if [[ ! "${AUTH_USERS[@]}" =~ "$usr" ]]; then
        echo $usr is unauthenticated
#       echo "Delete unauthenticated user $usr?"
#       select yn in "Yes" "No"; do
#           case $yn in
#               Yes ) userdel $usr 
#           esac
#       done
    fi
    usermod $usr --password $pass

done

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
section "/etc/passwd"
grep :0: /etc/passwd
ready "Inspect users with UID / GID 0"
vim /etc/passwd

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
section "Inspect /etc/group"
grep adm /etc/group
grep sudo /etc/group
ready "Inspect"
vim /etc/group

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
section "visudo"
#echo "Copy the following lines:"
#echo "Defaults log_output"
#echo "Defaults!/usr/bin/sudoreplay !log_output"
#echo "Defaults!/sbin/reboot !log_output"
ready "Press [ENTER] to launch visudo"
sudo visudo

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
section "Update unattended upgrades"
apt -my install unattended-upgrades >/dev/null
# TODO: Search for unattended upgrades
todo "Implement"
bash

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
section "Firefox Settings"
todo "Make Firefox Default Browser"
todo "Secure settings"

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
section "Inspect SSH config"
ready
vim -d /etc/ssh/sshd_config $BASE/rc/sshd_config
service sshd restart
# TODO: Integrate lynis

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
section "Audit media files"
MP3=$(find /home -name "*.mp3")
OGG=$(find /home -name "*.ogg")
MP4=$(find /home -name "*.mp4")
M4R=$(find /home -name "*.m4r")
JPG=$(find /home -name "*.jp*")
PNG=$(find /home -name "*.png")
media_files=($MP3 $OGG $MP4 $M4R $JPG $PNG)
echo "Media Files (mp3 ogg mp4 m4r jp* png):"
for file in ${media_files[@]}
do
    echo "--> $file"
done
read -rp "Delete these files? [y/N] " flag
if [ $flag = "y" ];
then
    echo "Deleting media files in 5s... "
    sleep 5
    for file in ${media_files[@]}
    do
        rm $file
    done
else
    echo "Files kept"
fi
ready "Look for other insecure files\nFor example: password.txt users.html etc."
bash

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
section "Disable guest login... "
read -rp "OS = Ubuntu with lightdm?" flag
if [ $flag = "y" ];
then
    ready
    echo "" > .temp
    while read line
    do
        if [[ ! $line =~ ^allow-guest=[a-z]+ ]];
        then
            echo $line >> .temp
        fi
    done < /etc/lightdm/lightdm.conf
    echo "allow-guest=false" >> .temp

    cat .temp > /etc/lightdm/lightdm.conf # If I use cat > instead of move, permissions should remain
    cat .temp > /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf
fi

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
section "Inspect sources"
ready "vim"
vim /etc/apt/sources.list
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
section "Firewall"
apt install -y ufw
ufw enable
ufw allow ssh
ufw allow http
ufw allow https
ufw default deny incoming
ufw default allow outgoing
ufw reject telnet
echo "Allows outgoing traffic by default"
echo "Denies incoming traffic by default"
echo "Allows: SSH, HTTP, HTTPS"
ready "Further secure UFW settings according to README"
bash

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
section "Inspect services"
echo " [+] : running"
echo " [-] : stopped"
echo " [?] : upstart service / status unsupported"
ready "Press [ENTER] to get list of services (pager)"
service --status-all | sort
ready "Inspect"
bash

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
section "Install sysctl.conf"
cat $BASE/rc/sysctl.conf > /etc/sysctl.conf
sysctl -e -p /etc/sysctl.conf
ready "Press [ENTER]"

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
section "Password policies"
ready 'Install pam configuration files'
cat $BASE/rc/common-password > /etc/pam.d/common-password
cat $BASE/rc/common-auth > /etc/pam.d/common-auth
ready 'Install login.def and host.conf'
cat $BASE/rc/login.defs > /etc/login.defs
cat $BASE/rc/host.conf > /etc/host.conf
ready "Read checklist and look for more fixes"
bash

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
section "Read README again"
todo "Take action"
bash

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
section "Software Audit"
read -rp "Should apache2 be removed? [y/N] " flag
if [ $flag = "y" ];
then
    echo "Removing apache2..."
    apt-get -my purge apache2 &> /dev/null # so it's silent
else
    echo "Will not remove apache2."
fi

read -rp "Should samba be removed? [y/N] " flag
if [ $flag = "y" ];
then
    echo "Removing samba..."
    apt-get -my purge samba* &> /dev/null # so it's silent
else
    echo "Will not remove samba."
fi

read -rp "Should vsftpd/openssh-sftp-server be removed? [y/N] " flag
if [ $flag = "y" ];
then
    echo "Removing vsftpd..."
    apt-get -my purge vsftpd openssh-sftp-server &> /dev/null # so it's silent
else
    echo "Will not remove vsftpd/openssh-sftp-server."
fi

ready "Removing hydra nmap zenmap john ftp telnet bind9 medusa vino netcat*"
echo "Removing in 5s"
sleep 5
apt -my purge hydra nmap zenmap john ftp telnet bind9 medusa vino netcat* > /dev/null
ready "Look for any disallowed package / software"
bash
ready "Press [ENTER] to upgrade"
apt update && apt upgrade

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
section "Inspect ports"
netstat -plant
ready "Inspect"
bash

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
section "Cron"
ready "Check root cron"
crontab -e
ready "Check all user cron"
bash
ready "Check /etc/cron*"
bash

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
section "File Permissions"

todo "Press [ENTER] to change permissions of passwd-related files"
chmod 644 /etc/passwd
chown root:root /etc/passwd
chmod 644 /etc/group
chown root:root /etc/group
chmod 600 /etc/shadow
chown root:root /etc/shadow
chmod 600 /etc/gshadow
chown root:root /etc/gshadow
chmod 700 /boot

todo "Press [ENTER] to change cron files' permissions"
chown root:root /etc/anacrontab
chmod og-rwx /etc/anacrontab
chown root:root /etc/crontab
chmod og-rwx /etc/crontab
chown root:root /etc/cron.hourly
chmod og-rwx /etc/cron.hourly
chown root:root /etc/cron.daily
chmod og-rwx /etc/cron.daily
chown root:root /etc/cron.weekly
chmod og-rwx /etc/cron.weekly
chown root:root /etc/cron.monthly
chmod og-rwx /etc/cron.monthly
chown root:root /etc/cron.d
chmod og-rwx /etc/cron.d

ready "Malware checks"
ready "Rkhunter check"
apt -my install rkhunter >/dev/null
rkhunter --check

#
sudo apt install

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
section "Find more checklists"
# TODO: look for checklists in walnut csc folder; integrate into script
# TODO: integrate starred checklist in drive (Ubuntu checklist (cypa))
todo "run lynis"
todo "in gdm3 greeter defaults config, disable-user-list=true"
todo "check executables with find / -perm /4000 2>/dev/null"
todo "ensure ufw allows critical servers"
todo "check sticky bit perm"
todo "set apt settings see phone picture"
todo "add a grub password, check signature"
todo "secure fstab"
todo "use chage if needed"
todo "secure shm (shared memory) in fstab"
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
