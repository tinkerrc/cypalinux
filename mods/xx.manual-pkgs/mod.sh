pkglist=/var/log/installer/initial-status.gz
if [ -f "$RC/$OS/initial-status.gz" ]; then
    pkglist="$RC/$OS/initial-status.gz"
fi
comm -23 <(apt-mark showmanual | sort -u) <(gzip -dc $pkglist | sed -n 's/^Package: //p' | sort -u) | tee "$DATA/manually-installed"
psuccess "Nonpreinstalled packages have been stored into \$DATA/manually-installed"
