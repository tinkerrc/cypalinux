#!/usr/bin/env bash
# NOTE: fs-compare uses $BACKUP/{etc,var} by default
# NOTE: Slash placement matter!

pinfo "Please note that fs-compare compares stock /{etc,var} with BACKED-UP /{etc,var}."

if ! [[ -d $RC/$OS ]]; then
    perror "Resource directory for $OS does not exist."
    exit
fi

if ! [[ -d $DATA/etc ]]; then
    unzip "$RC/$OS/etc.zip" -d "$DATA/"
fi
if ! [[ -d $DATA/var ]]; then
    unzip "$RC/$OS/var.zip" -d "$DATA/"
fi

ready "Compare backed-up (original) /etc with blank image"
rsync -nrvc --delete "$DATA/etc/" "$BACKUP/etc"

ready "Compare backed-up (original) /var with blank image"
rsync -nrvc \
    --exclude /cache/ \
    --exclude /lib/ \
    --exclude /backups/ \
    --exclude /log/ \
    --delete" $DATA/var/" "$BACKUP/var"
