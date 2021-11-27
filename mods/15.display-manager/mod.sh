if [ -d /etc/lightdm ]; then
    instconf $RC/lightdm.conf /etc/lightdm/lightdm.conf
fi
if [ -d /etc/gdm3 ]; then
    # TODO: replace with a new file, don't edit
    sed -i 's/^.*disable-user-list.*$/disable-user-list=true/' /etc/gdm3/greeter.dconf-defaults
    sed -i 's:^.*\[org/gnome/login-screen\].*$:[org/gnome/login-screen]:' /etc/gdm3/greeter.dconf-defaults
fi
