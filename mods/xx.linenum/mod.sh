#!/usr/bin/env bash
if [[ ! -d $DATA/LinEnum ]]; then
    pinfo "Acquiring script"
    git clone https://github.com/rebootuser/LinEnum $DATA/LinEnum
fi
chmod +x $DATA/LinEnum/LinEnum.sh

cwd=$(pwd)
cd /tmp
pinfo "Starting linenum in 5 seconds"
sleep 5
$DATA/LinEnum/LinEnum.sh -t -r linenum-report
cd $cwd

pinfo "View report in $(echo /tmp/linenum-report-*)"
