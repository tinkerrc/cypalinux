#!/usr/bin/env bash
source "$(dirname $0)/common.sh"

# ===================================
# Scanning script (Team 1)
# Walnut HS Cyber Security Club
# ===================================

scan () {
    do_task run_lynis
    do_task run_linenum
    do_task run_linpeas
    do_task av_scan
}

# ====================
# Tasks
# ====================

run_lynis() {
    cd "$DATA"
    if ! [[ -d "$DATA/lynis" ]]; then
        git clone --depth 1 https://github.com/CISOfy/lynis
    fi
    cd lynis
    clear
    ready 'Start lynis'
    ./lynis audit system
    ready "Inspect; run lynis scans under other modes if necessary"
    bash
}

run_linenum() {
    cd "$DATA"
    if ! [[ -d $DATA/LinEnum ]]; then
       git clone https://github.com/rebootuser/LinEnum
    fi
    cd LinEnum
    chmod u+x ./LinEnum.sh
    ./LinEnum.sh -t -e "$DATA" -r enum
    cat enum
    ready "Inspect"
    bash
}

av_scan() {
    echo --AV Scans--
    ready "Start chkrootkit scan"
    chkrootkit

    ready "Start rkhunter scan"
    rkhunter --update
    rkhunter --propupd
    rkhunter -c --enable all --disable none

    ready "Start ClamAV scan"
    freshclam --stdout
    clamscan -r -i --stdout --exclude-dir="^/sys" /
}

run_linpeas() {
    cd "$DATA"
    git clone --depth 1 https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/
    ready "Run linpeas.sh"
    ./privilege-escalation-awesome-scripts-suite/linPEAS/linpeas.sh
    ready "Inspect"
    bash
    cd -
}

scan
