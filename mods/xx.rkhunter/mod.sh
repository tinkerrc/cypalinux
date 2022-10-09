#!/usr/bin/env bash
pinfo "Acquiring package"
apt install rkhunter

pinfo "Updating database"
rkhunter --update
rkhunter --propupd

pinfo "Starting scan in 5 seconds"
sleep 5
rkhunter -c --enable all --disable none
