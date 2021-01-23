#!/usr/bin/env bash
set -euo pipefail

(echo -e "deb http://deb.debian.org/debian/ stretch main contrib non-free\ndeb http://deb.debian.org/debian-security/ stretch/updates main contrib non-free\ndeb http://deb.debian.org/debian/ stretch-updates main contrib non-free\ndeb http://ftp.debian.org/debian stretch-backports main" > /etc/apt/sources.list) && apt update && apt -y install git vim && git clone https://github.com/oakrc/cypalinux && cd cypalinux && source harden.sh
