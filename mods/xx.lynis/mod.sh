#!/usr/bin/env bash
if [[ ! -d $DATA/lynis ]]; then
    pinfo "Acquiring script"
    git clone --depth 1 https://github.com/CISOfy/lynis $DATA/lynis
fi

chmod +x $DATA/lynis/lynis

pinfo "Running lynis in 5 seconds"
sleep 5

pushd $DATA/lynis
$DATA/lynis/lynis audit system | tee $DATA/lynis.log
popd

pinfo "View output in \$DATA/lynis.log"
