#!/usr/bin/env bash
cd "$DATA"
if [[ ! -d $DATA/peas ]]; then
    pinfo "Acquiring script"
    git clone --depth 1 https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/ $DATA/linpeas
fi
pinfo "Running linpeas in 5 seconds"
sleep 5
$DATA/linpeas/linPEAS/linpeas.sh -s | tee $DATA/linpeas.log

pinfo "View output in \$DATA/linpeas.log"
