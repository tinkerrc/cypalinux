#!/usr/bin/env bash
chown root:root /
chmod 751 /

# ===== Boot =====
chown root:root /boot
chmod 700 /boot

chown -R root:root /boot/grub
chmod 600 /boot/grub/grub.cfg

# ===== tmp =====
chown root:root /tmp
chmod 1777 /tmp
chown root:root /var/tmp
chmod 1777 /var/tmp

# ===== etc =====
chown root:root /etc
chmod -R o-w /etc

chown -R root:root /etc/default
chmod 755 /etc/default
chmod 644 /etc/default/*

chown -R root:root /etc/grub.d
chmod -R 755 /etc/grub.d/*_*

chown root:root /etc/resolv.conf
chmod 644 /etc/resolv.conf

chown root:root /etc/fstab
chmod 664 /etc/fstab

# ===== User Management =====
chown root:root /etc/passwd
chmod 644 /etc/passwd

chown root:root /etc/passwd-
chmod 644 /etc/passwd-

chown root:root /etc/group
chmod 644 /etc/group

chown root:root /etc/group-
chmod 644 /etc/group-

chown root:root /etc/shadow
chmod 600 /etc/shadow

chown root:root /etc/shadow-
chmod 600 /etc/shadow-

chown root:root /etc/gshadow
chmod 600 /etc/gshadow

chown root:root /etc/gshadow-
chmod 600 /etc/gshadow-

chown root:root /etc/opasswd 2>/dev/null
chmod 600 /etc/opasswd 2>/dev/null

chown root:root /etc/security/opasswd
chmod 600 /etc/security/opasswd

chown root:root /etc/login.defs
chmod 644 /etc/login.defs

chown root:root /etc/sudoers
chmod 400 /etc/sudoers

chown -R root:root /etc/sudoers.d
chmod 750 /etc/sudoers.d
if ! [ -n "$(find /etc/sudoers.d -prune -empty)" ]; then
    chmod 400 /etc/sudoers.d/*
fi

chown -R root:root /etc/pam.d
chmod 755 /etc/pam.d
chmod 644 /etc/pam.d/*

# ===== Security =====
chown -R root:root /etc/security
chmod 755 /etc/security
# There is a file called namespace.init that needs x bit
chmod go-w /etc/security

# ===== Cron =====
chown root:root /etc/anacrontab
chmod 640 /etc/anacrontab

chown root:root /etc/crontab
chmod 640 /etc/crontab

chown -R root:root /etc/cron.hourly
chmod 750 /etc/cron.hourly

chown -R root:root /etc/cron.daily
chmod 750 /etc/cron.daily

chown -R root:root /etc/cron.weekly
chmod 750 /etc/cron.weekly

chown -R root:root /etc/cron.monthly
chmod 750 /etc/cron.monthly

chown -R root:root /etc/cron.d
chmod 750 /etc/cron.d

# ===== Environment =====
chown root:root /etc/environment
chmod 644 /etc/environment

chown root:root /etc/profile
chmod 644 /etc/profile

chown root:root /etc/bash.*
chmod 644 /etc/bash.*

chown root:root /etc/host*
chmod 644 /etc/host*

# ===== Misc. =====
chmod 700 /boot 
chmod 700 /usr/src
chmod 700 /lib/modules
chmod 700 /usr/lib/modules

# ===== Home =====
chown root:root /home
chmod 755 /home

chown root:root /root
chmod 700 /root

for home in /home/*; do
    user=$(basename $home)
    chown -R $user:$user $home
    chmod 700 $home
    if [[ -d $home/.ssh ]]; then
        chmod 700 $home/.ssh 
        chmod 600 $home/.ssh/*
    fi
    if [[ -d $home/.gnupg ]]; then
       chmod 700 $home/.gnupg
       chmod 600 $home/.gnupg/*
    fi
done

psuccess "Corrected common file permissions"
