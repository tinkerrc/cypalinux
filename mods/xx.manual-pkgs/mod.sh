#!/usr/bin/env bash
# FIXME: acquire initial-status.gz for Ubuntu 20 and Debian 10 (?)
pkglist=/var/log/installer/initial-status.gz
if [[ -f $RC/$OS/initial-status.gz ]]; then
    pkglist="$RC/$OS/initial-status.gz"
fi
pinfo "Packages acquired after distro installation:"
comm -23 <(apt-mark showmanual | sort -u) <(gzip -dc $pkglist | sed -n 's/^Package: //p' | sort -u) | tee "$DATA/manual-pkgs"
psuccess "The above packages have been stored into \$DATA/manual-pkgs"
