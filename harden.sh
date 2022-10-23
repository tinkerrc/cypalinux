#!/usr/bin/env bash

#   ==================================
#   | Walnut HS Cyber Security Club  |
#   |            Team 1              |
#   |     Linux Hardening Script     |
#   ==================================

if [[ -z $DRYRUN ]]; then
    DRYRUN=false
fi

set -au
unalias -a
umask 0027

# ====================
# Sanity Checks
# ====================
# We require the script to be run as root.
# Save time by not typing sudo all the time.
if [[ ! $(whoami) = root && ! $DRYRUN = true ]]; then
    echo "Please try again with root privileges..."
    # return if sourced, otherwise exit
    return 1 2>/dev/null || exit 1
fi

# Make sure the script better better better better was sourced, not run directly
# Ensure accessibility of functions and variables when modules are rerun
if [[ ${BASH_SOURCE[0]} == ${0} ]]; then
    echo "Run 'source harden.sh' instead"
    exit 1
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
elif (lsb_release -a 2>/dev/null | grep -q 'Debian.* 8'); then
    OS=d8
elif (lsb_release -a 2>/dev/null | grep -q 'Debian.* 9'); then
    OS=d9
elif (lsb_release -a 2>/dev/null | grep -q 'Debian.* 10'); then
    OS=d10
elif (lsb_release -a 2>/dev/null | grep -q 'Debian.* 11'); then
    OS=d11
elif [[ $DRYRUN = true ]]; then
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
RUNLOG="/cypa/run.log"
DEBIAN_FRONTEND=noninteractive
EDITOR=vim
TERM=xterm-256color

mkdir -p "$DATA"

# Re-enable root bash_history
if [[ -L /root/.bash_history && ! $DRYRUN = true ]]; then
    unlink /root/.bash_history
    echo -n > /root/.bash_history
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
    mv $2{,.bak}
    mkdir -p $2
    pushd $1
    find . -type f -exec install -o root -g root -Dm644 {} $2/{} \;
    popd
}

# Logging
red="\x1b[38;2;255;23;68m"
green="\x1b[38;2;0;230;118m"
blue="\x1b[38;2;0;176;255m"
orange="\x1b[38;2;255;191;0m"
gray="\x1b[38;2;153;153;153m"
purple="\x1b[38;2;234;128;252m"
reset="\x1b[0m"

pdate() {
    date --rfc-3339=seconds
}
psuccess() {
    echo -e "$green$*$reset"
    echo -e "`pdate`  SUC: $*" >> $RUNLOG
}
pinfo() {
    echo -e "$blue$*$reset"
    echo -e "`pdate`  INF: $*" >> $RUNLOG
}
pwarn() {
    echo -e "$orange$*$reset" >&2
    echo -e "`pdate`  WRN: $*" >> $RUNLOG
}
perror() {
    echo -e "$red$*$reset" >&2
    echo "`pdate`  ERR: $*" >> $RUNLOG
    echo "`pdate`  $*" >> $ERRLOG
}
pignore() {
    echo -e "$gray$*$reset"
    echo "`pdate`  IGN: $*" >> $RUNLOG
}
ptodo() {
    echo -e "$purple$*$reset"
    echo "$*" >> "$DATA/todo"
    echo "`pdate`  TDO: $*" >> $RUNLOG
}
pmodule() {
    echo -e "${purple}-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=$reset"
    echo -e "${purple}     Module :: $*$reset" 
    echo -e "${purple}-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=$reset"
    echo >> $RUNLOG
    echo "`pdate`  MOD: $*" >> $RUNLOG
}

# Prompts
todo() {
    # Follow the instruction; might have to leave terminal
    echo -e "${red}TODO:$reset $*"
    sleep 0.1
    read -n 1 -rp $'\x1b[38;2;153;153;153mPress [ENTER] when you finish\x1b[0m'
}
ready() {
    # Wait for user to be ready
    if [[ $* != '' ]]; then
        echo -e "${purple}READY:$reset $*"
    fi
    sleep 0.1
    read -n 1 -rp $'\x1b[38;2;153;153;153mPress [ENTER] when you are ready\x1b[0m'
}

# Package Management
apti() {
    local packages=""
    for i in "$@"; do 
        if ! [[ -z $(apt-cache madison $i 2>/dev/null) ]]; then
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
    grep -Eq "^(..\\.)?$*\$" "$DATA/config"
}
mask() {
    touch $BASE/mods/??.${1}/masked
}
unmask() {
    rm -f $BASE/mods/??.${1}/masked
}
moddir() {
    echo -n $BASE/mods/??.${1}/
}
# Converts module path to module name
modname() {
    basename $1 | cut -c 4-
}
# Converts module path to module priority
modpri() {
    basename $1 | cut -c -2
}

# Services
add-crontab() {
    crontab -l > "$DATA/crontab"
    echo "$1" >> "$DATA/crontab"
    crontab "$DATA/crontab"
}
disnow() {
    systemctl disable --now $1
}

# Misc
blank() {
    echo -n > $1
}
print() {
    echo -n $@
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
#    | mods.sh         -- will be run regardless (unless manually removed from merged config)
#    | use.sh          -- will be run if module name is kept in user config
#    | disuse.sh       -- will be run if module name is removed from user config
#    | pkgs            -- contains list of packages required by this module
#    | masked          -- if present, completely ignore this module as if it does not exist
#    | is_interactive  -- mark module as interactive (may require user input)

# runs all unmasked nonmanual modules
harden() {
    # TODO: https://madaidans-insecurities.github.io/guides/linux-hardening.html
    # TODO: compare file system (file names, contents, and permissions; with ignored directories, don't descend into unrecognized dirs)
    # TODO: add more todos from remnote
    # TODO: new module: xx.scap -- scan system with scap-security-guide and openscap
    # TODO: https://github.com/trimstray/the-practical-linux-hardening-guide
    # TODO: acquire a list of services from all possible distros (for diffing against)
    # TODO: https://www.open-scap.org/security-policies/scap-security-guide/#install
    # TODO: systemd/{system,user}.comf

    for dir in $BASE/mods/??.*/; do
        if [[ $(modpri $dir) != xx ]]; then
            mod $(modname $dir)
        fi
    done
}
# runs a single unmasked module
mod() {
    if [[ -z $1 ]]; then
        perror "No module name specified"
        return 1
    fi

    local mod=$1
    MOD=$(echo $BASE/mods/??.$mod)
    RC=$MOD/rc
    mkdir -p $DATA/mods/

    if [[ ! -d $MOD ]]; then
        perror "Module $mod does not exist"
        return 1
    fi

    if [[ -f $MOD/masked ]]; then
        perror "Module $mod is masked"
        return 1
    fi

    pmodule $mod

    if [[ $DRYRUN = true ]]; then
        pignore "Module $mod will be ignored (dry run)"
        return
    fi

    if [[ -f $DATA/mods/$mod ]]; then
        pwarn "Rerunning module $1"
    fi

    # Install dependencies for manually run modules.
    # Dependencies for normal modules are managed by mod-deps
    if [[ $(modpri $mod) = xx && -f $MOD/pkgs && ! -f $MOD/pkgs_installed ]]; then
        pinfo "Installing dependencies"
        apt install -y $(cat $MOD/pkgs)
        touch $MOD/pkgs_installed
        psuccess "Installed dependencies"
    fi

    local status=ok
    # If config exists, run mod.sh if module name is found
    # If config does not exist, always run mod.sh
    if [[ -f $MOD/mod.sh ]] && ( [[ ! -f $DATA/config ]] || use $mod ) ; then
        pinfo "Running $mod/mod.sh"
        bash $MOD/mod.sh || status=failed
    fi

    # If config does not exist, do nothing
    # If config exists, run use.sh if this module name is found, run disuse.sh otherwise
    if [[ ! -e $DATA/config ]]; then
        :
    elif use $mod && [[ -f $MOD/use.sh ]]; then
        pinfo "Running $mod/use.sh"
        bash $MOD/use.sh || status=failed
    elif ! use $mod && [[ -f $MOD/disuse.sh ]]; then
        pinfo "Running $mod/disuse.sh"
        bash $MOD/disuse.sh || status=failed
    fi

    touch $DATA/mods/$mod
    [[ $status = failed ]] && perror "Module $mod finished with errors"
}

psuccess "Invoke 'harden' to secure to machine"

# vim: autoindent expandtab smarttab tabstop=4 shiftwidth=4
