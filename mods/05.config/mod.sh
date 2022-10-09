#!/usr/bin/env bash
blank $DATA/mods.configurable
blank $DATA/mods.always_on
blank $DATA/config

for dir in $BASE/mods/*/; do
    mod=$(modname $dir)
    priority=$(modpri $dir)

    if [[ -f $dir/masked || $priority = xx ]]; then
        continue
    fi

    if [[ -f $dir/use.sh || -f $dir/disuse.sh ]]; then
        echo $mod >> $DATA/mods.configurable
    else
        echo $mod >> $DATA/mods.always_on
    fi
done
cp -f $DATA/mods.configurable $DATA/mods.enabled

ready "Edit config (remove line to disable an optional module)"
vim $DATA/mods.enabled
cat $DATA/mods.enabled $DATA/mods.always_on > $DATA/config

ready "Enter a list of ALL authorized users (incl. admins)"
vim $DATA/authorized_users

ready "Enter a COMMA-SEPARATED list of authorized admins"
vim $DATA/authorized_sudoers

ready "Enter the name of the autologin user"
vim $DATA/autologin_user
