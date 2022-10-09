#!/usr/bin/env bash
for home in /home/*/; do
    user=$(basename $home)
    for profile in $home/.mozilla/firefox/*.*/; do
        install -o $user -g $user -Dm660 $RC/user.js $profile/user.js
    done
done

if [[ $OS = d* ]]; then
    instconf $RC/debian_locked.js /etc/firefox-esr/firefox-esr.js
    killall firefox-esr
else
    instconf $RC/locked_user.js /etc/firefox/syspref.js # older
    instconf $RC/locked_user.js /etc/firefox/firefox.js # newer
    killall firefox
fi
ptodo "Restart Firefox"
psuccess "Configured all firefox profiles"
