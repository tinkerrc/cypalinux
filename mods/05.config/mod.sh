rm $DATA/mods.configurable
touch $DATA/mods.configurable
rm $DATA/mods.always_on
touch $DATA/mods.always_on

for dir in $BASE/mods/*/; do
    mod=$(getmodname $dir)
    priority=$(getmodpri $dir)

    if [ -f $dir/masked -o "$priority" = xx ]; then
        continue
    fi

    if [ -f $dir/use.sh -o -f $dir/disuse.sh ]; then
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

read -p $'\x1b[38;2;255;61;0mPress [ENTER] to start\x1b[0m'
