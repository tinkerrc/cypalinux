#!/usr/bin/env bash
if [[ ! -f $DATA/backed-up ]]; then
    pinfo "Backing up files..."
    mkdir -p "$BACKUP"
    cp -a /home /etc /var "$BACKUP"
    psuccess "/home /etc /var backed up"
    touch "$DATA/backed-up"
else
    psuccess "Already backed up"
fi
