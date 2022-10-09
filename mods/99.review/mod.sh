#!/usr/bin/env bash
if [[ -f $ERRLOG ]]; then
    echo -en "$red"
    sort -u "$ERRLOG"
    pinfo "Please review the above errors"
fi

ptodo "Run mod fs-compare"
ptodo "Run lynis, linenum, and linpeas"
ptodo "Run mod debsums"
ptodo "Run mod rkhunter"

echo -e "$purple"
sort -u "$DATA/todo"
pinfo "Please review the above to-do's"

echo -en "$reset"

if [[ ! -f $DATA/test ]]; then
    pinfo "Please proceed with the checklist"
fi
psuccess "Hardening completed"
