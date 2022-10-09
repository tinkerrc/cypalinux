#!/usr/bin/env bash
pinfo "Installing package lists"
instconf "$RC/$OS/sources.list" /etc/apt/sources.list

pinfo "Updating APT package lists"
apt update -q
psuccess "APT package lists updated successfully"
