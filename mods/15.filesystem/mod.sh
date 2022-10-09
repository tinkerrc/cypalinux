#!/usr/bin/env bash
echo "tmpfs      /dev/shm    tmpfs   defaults,rw,noexec,nodev,nosuid,relatime   0 0" >> /etc/fstab
echo "tmpfs      /tmp        tmpfs   defaults,rw,noexec,nodev,nosuid,relatime   0 0" >> /etc/fstab
echo "tmpfs      /var/tmp    tmpfs   defaults,rw,noexec,nodev,nosuid,relatime   0 0" >> /etc/fstab

instconf $RC/updatedb.conf /etc/updatedb.conf
pinfo "Updating locate database"
updatedb
pinfo "locate database updated"

mkdir -p "$BACKUP/quarantine"
# TEST: whether xargs works
locate -0 -i --regex \
    "^/home/.*\.(aac|avi|flac|flv|m4a|mkv|mov|mp3|mp4|mpeg|mpg|ogg|rmvb|wma|wmv)$" | \
    grep -Ev '.config|.local|.cache|Wallpaper' | tee "$DATA/banned_files" | xargs -r0 sh -c "chattr -i -a \$(basename _) && chattr -i -a _ && mv -t $BACKUP/quarantine _" || perror "Couldn't quarantine files"
locate -0 -i --regex \
    "\.(aac|avi|flac|flv|gif|jpeg|jpg|m4a|mkv|mov|mp3|mp4|mpeg|mpg|ogg|png|rmvb|wma|wmv)$" | \
    grep -Ev '^(/usr|/var/lib)' | tee "$DATA/sus_files"

ptodo "Check \$DATA/banned_files and \$BACKUP/quarantine for successful removal of banned files"
ptodo "Check \$DATA/sus_files for suspicious files"
psuccess "Media files in /home are quarantined in \$BACKUP/quarantine (see \$DATA/banned_files)."
