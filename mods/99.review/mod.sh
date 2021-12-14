if [[ -f $ERRLOG ]]; then
    echo -en "$red"
    sort -u "$ERRLOG"
    ptodo "Please review the above errors"
fi

ptodo "Run lynis, linenum, and linpeas"
echo -e "$purple"
sort -u "$DATA/todo"
ptodo "Please review the above to-do's"

echo -en "$reset"

if [[ ! -f $DATA/test ]]; then
    pinfo "Please proceed with the checklist"
fi
psuccess "Hardening completed"
