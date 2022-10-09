#!/usr/bin/env bash
pinfo "Beginning APT upgrade in 5 seconds, consider doing forensics questions in the meanwhile"
sleep 5
apt full-upgrade -y && psuccess "Completed system upgrade" || perror "System upgrade failed"
