if [ -f "$ERRLOG" ]; then
    echo -en "$red"
    cat "$ERRLOG"
fi
if [ -f "$DATA/todo" ]; then
    echo -e "$purple"
    cat "$DATA/todo"
fi
echo -en "$reset"
