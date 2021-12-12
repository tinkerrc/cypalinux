#!/usr/bin/env bash
set -au
unalias -a
umask 027

#   ==================================
#   |     Linux Hardening Script     |
#   | Walnut HS Cyber Security Club  |
#   ==================================

# ====================
# Sanity Checks
# ====================
DRYRUN=false

# Save time by not typing sudo all the time
if [ ! "$(whoami)" = "root" -a ! "$DRYRUN" = "true" ]; then
    echo "Please try again with root privileges..."
    return 1
fi

# Make sure the script was sourced, not run directly
# Ensure accessibility of functions and variables when modules are rerun
if [ "${BASH_SOURCE[0]}" != "${0}" ]; then
    echo "Invoke harden to secure the machine"
else
    echo "Run 'source harden.sh' instead"
    return 1
fi

# ====================
# Set up environment
# ====================

# OS Detection
if (lsb_release -a 2>/dev/null | grep -q 16.04); then
    OS=u16
elif (lsb_release -a 2>/dev/null | grep -q 18.04); then
    OS=u18
elif (lsb_release -a 2>/dev/null | grep -q 20.04); then
    OS=u20
elif (lsb_release -a 2>/dev/null | grep -q 'Debian 8'); then
    OS=d8
elif (lsb_release -a 2>/dev/null | grep -q 'Debian 9'); then
    OS=d9
elif (lsb_release -a 2>/dev/null | grep -q 'Debian 10'); then
    OS=d10
elif (lsb_release -a 2>/dev/null | grep -q 'Debian 11'); then
    OS=d11
elif [ "$DRYRUN" = "true" ]; then
    OS=u18
else
    echo "Failed to identify OS version"
    return 1
fi

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
BASE="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &>/dev/null && pwd )"
DATA="/cypa/data"
BACKUP="/cypa/backup" # created by mod.backup
ERRLOG="/cypa/errors.log"
DEBIAN_FRONTEND=noninteractive

mkdir -p "$DATA"

if [[ -L /root/.bash_history && ! $DRYRUN = true ]]; then
    unlink /root/.bash_history
    echo '' > /root/.bash_history
fi

# ====================
# Utilities
# ====================

# Config files
instconf() {
    install --backup -o root -g root -Dm644 $1 $2
}
instsecret() {
    install --backup -o root -g root -Dm600 $1 $2
}
# instdir source/config_dir dest/config_dir
instdir() {
    mkdir -p $2
    pushd $1
    find . -type f -exec install -o root -g root -Dm644 {} $2/{} \;
    popd
}

# Logging
red="\x1b[38;2;255;23;68m"
green="\x1b[38;2;0;230;118m"
blue="\x1b[38;2;0;176;255m"
orange="\x1b[38;2;255;61;0m"
gray="\x1b[38;2;153;153;153m"
purple="\x1b[38;2;234;128;252m"
reset="\x1b[0m"

psuccess() {
    echo -e "$green$*$reset"
}
pinfo() {
    echo -e "$blue$*$reset"
}
pwarn() {
    echo -e "$orange$*$reset"
}
perror() {
    echo -e "$red$*$reset"
    echo "$*" >> $ERRLOG
}
pignore() {
    echo -e "$gray$*$reset"
}
pmodule() {
    echo -e "${purple}-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=$reset"
    echo -e "${purple}     Module :: $*$reset" 
    echo -e "${purple}-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=$reset"
    sleep 0.3
}

# Prompts
todo () {
    # Follow the instruction; might have to leave terminal
    echo -e "${red}TODO:$reset $*"
    sleep 0.1
    read -n 1 -rp "Press [ENTER] when you finish"
}
ready() {
    # Wait for user to be ready
    if [ "$*" != "" ]; then
        echo -e "${purple}READY:$reset $*"
    fi
    sleep 0.1
    read -n 1 -rp "Press [ENTER] when you are ready"
}

# Package Management
apti() {
    local packages=""
    for i in "$@"; do 
        if ! [ -z "$(apt-cache madison $i 2>/dev/null)" ]; then
            packages="$packages $i"
        fi
    done
    apt install -y $packages
}
aptr() {
    local packages=""
    for i in "$@"; do 
        if dpkg -s $1 &>/dev/null; then
            packages="$packages $i"
        fi
    done
    apt remove -y $packages
}
aptar() {
    apt -y autoremove
}

# Modules
use() {
    grep -E "^(..\\.)?$*\$" "$DATA/config"
}
mask() {
    touch $BASE/mods/??.${1}/masked
}
unmask() {
    rm -f $BASE/mods/??.${1}/masked
}
getmodname() {
    basename $1 | cut -c 4-
}
getmodpri() {
    basename $1 | cut -c -2
}

# Cron
add-crontab() {
    crontab -l > "$DATA/crontab"
    echo "$1" >> "$DATA/crontab"
    crontab "$DATA/crontab"
}

# ====================
# Main
# ====================

# - Modules must be able to access MOD=$BASE/mods/mod_name RC=$MOD/rc
# - A module must have mod.sh, or if nonexistent, one or both of use.sh and
#   disuse.sh 
# - if the latter files exist, then the module must be considered in 03.config
# - Modules may register packages that must be installed if module is used and
#   removed otherwise
# - Modules whose priority is xx (e.g., xx.lynis) can only be run manually
#   (i.e., through run())

# - Module FS layout
#    +-- /mods/mod_name/
#    | mods.sh         -- will be run regardless
#    | use.sh          -- will be run if module name is kept in config
#    | disuse.sh       -- will be run if module name is removed from config
#    | pkgs            -- contains list of packages required by this module
#    | is_interactive  -- mark module as interactive (may require user input)
#    | masked          -- completely ignore this module as if it DNE

# runs all unmasked nonmanual modules
harden() {
    # TODO: add more todos from remnote
    # TODO: new module: xx.scap -- scan system with scap-security-guide and openscap
    # TODO: https://github.com/trimstray/the-practical-linux-hardening-guide
    # TODO: https://www.open-scap.org/security-policies/scap-security-guide/#install

    # primoddir = $BASE/mods/??.mod_name/
    for primoddir in $BASE/mods/*/; do
        # primod = ??.mod_name
        local primod=$(basename $primoddir)
        # pri = ??.
        local pri=$(echo $primod | cut -c -3)
        # mod = mod_name
        local mod=$(echo $primod | cut -c 4-)

        if [[ $pri != xx. ]]; then
            run-mod $mod
        fi
    done
}
# runs a single unmasked module
run-mod() {
    if [[ -z $1 ]]; then
        perror "No module name specified"
        return 1
    fi

    local mod=$1
    MOD=$BASE/mods/??.$mod
    RC=$MOD/rc

    if ! [[ -d $MOD ]]; then
        perror "Module $mod does not exist"
        return 1
    fi

    pmodule $mod

    if [[ -f $MOD/masked -o "$DRYRUN" = "true" ]]; then
        return
    fi
    
    if [[ -f $MOD/mod.sh ]]; then
        bash $MOD/mod.sh
    fi

    if use $mod && [[ -f $MOD/use.sh ]]; then
        bash $MOD/use.sh
    elif ! use $mod && [[ -f $MOD/disuse.sh ]]; then
        bash $MOD/disuse.sh
    fi
}

