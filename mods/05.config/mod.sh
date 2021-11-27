# TODO: print a list of colorcoded modules in config to distinguish active/inactive/interactive modules
# FIXME: dynamic config preset
#   when producing the dynamic config preset, also create a list
#   of modules that are always on and append this file to
#   $DATA/config at the end
# NOTE: don't include any module that are masked or manual!!
cp -f $BASE/config $DATA/config
ready "Edit config (remove line to disable an optional module)"
vim $DATA/config

ready "Enter a list of ALL authorized users (incl. admins)"
vim $DATA/authorized_users

ready "Enter a COMMA-SEPARATED list of authorized admins"
vim $DATA/authorized_sudoers

ready "Enter the name of the autologin user"
vim $DATA/autologin_user

read -p "${orange}Press [ENTER] to start$reset"
