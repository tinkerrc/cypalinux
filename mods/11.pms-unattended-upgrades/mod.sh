#!/usr/bin/env bash
dir=/etc/apt/apt.conf.d
mkdir -p "$dir" # should already be there
instconf $RC/10periodic $dir/10periodic
instconf $RC/50unattended-upgrades $dir/50unattended-upgrades
instconf $RC/50unattended-upgrades $dir/20auto-upgrades
psuccess "APT Unattended Upgrades configured"
