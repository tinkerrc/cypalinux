pinfo "Setting grub password (password is 'password')"
install -o root -g root -Dm755 $RC/40_custom /etc/grub.d/40_custom
# sed -i 's/^CLASS="--class gnu-linux --class gnu --class os"$/CLASS="--class gnu-linux --class gnu --class os --unrestricted"/' /etc/grub.d/10_linux
pinfo "Updating grub"
update-grub
psuccess "Grub updated and bootloader password applied"
