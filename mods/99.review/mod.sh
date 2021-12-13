if [ -f "$ERRLOG" ]; then
    echo -en "$red"
    sort -u "$ERRLOG"
fi
if [ -f "$DATA/todo" ]; then
    echo -e "$purple"
    sort -u "$DATA/todo"
fi
echo -en "$reset"
