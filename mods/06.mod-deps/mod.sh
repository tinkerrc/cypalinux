desired_pkgs=''
undesired_pkgs=''

# TODO: make pkgs a shell script instead

for dir in $BASE/mods/*/; do
    if [ ! -f $dir/masked -a -f $dir/pkgs ]; then
        if use $(getmodname $dir); then
            desired_pkgs="$desired_pkgs $(cat $dir/pkgs 2>/dev/null)"
        else
            undesired_pkgs="$undesired_pkgs $(cat $dir/pkgs 2>/dev/null)"
        fi
    fi
done

# Probably not necessary but replace newlines with spaces just in case
desired_pkgs=$(echo $desired_pkgs | tr '\n' ' ')
undesired_pkgs=$(echo $undesired_pkgs | tr '\n' ' ')

apt install -y $desired_pkgs || pwarn "Retrying installation in filtered mode" && apti $desired_pkgs || perror "Failed to install all dependencies"
apt remove -y $undesired_pkgs || pwarn "Retrying removel in filtered mode" && aptr $undesired_pkgs || perror "Failed to remove unnecessary packages"
psuccess "Finished handling module dependencies"
