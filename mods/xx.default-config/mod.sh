#!/usr/bin/env bash
pinfo "Please note that default-config compares stock /etc with CURRENT /etc."

if [[ -d $RC/$OS/etc.zip ]]; then
    if ! [[ -d $DATA/etc ]]; then
        unzip "$RC/$OS/etc.zip" -d "$DATA/"
    fi

    if diff --help | grep -q -- --color; then
        diff --color=always -r --no-dereference ${RC}/${OS}/etc /etc | less -R
    else 
        colordiff -r --no-dereference ${RC}/${OS}/etc /etc | less -R
    fi
else
    perror "Default config for this OS version not found"
fi
