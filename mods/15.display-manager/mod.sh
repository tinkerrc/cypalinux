#!/usr/bin/env bash
if grep -q lightdm /etc/X11/default-display-manager; then
    instconf $RC/lightdm.conf /etc/lightdm/lightdm.conf
    psuccess "Inspect /etc/lightdm"
fi
if grep -q gdm3 /etc/X11/default-display-manager; then
    instconf $RC/greeter.dconf-defaults /etc/gdm3/greeter.dconf-defaults
    instconf $RC/custom.conf /etc/gdm3/custom.conf
    # TEST: test whether autologin config works
    sed -i "s/AUTOLOGIN_USER/$(cat $DATA/autologin_user | xargs)/" /etc/gdm3/custom.conf
    psuccess "Inspect /etc/gdm3"
fi
