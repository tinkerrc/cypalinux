# TODO: manually inspect apache2 config (enabled vs disabled sites, conf, mod, etc.)
# TODO: test
# TODO: apache2 envvars (/etc/apache2/envvars)
instconf $RC/apache2.conf /etc/apache2/apache2.conf
instconf $RC/security.conf /etc/apache2/conf-available/security.conf
# NOTE: pkgs currently contain both the old and new modsecurity (older is for Debian); when mod-deps support distro version detection, change this
instconf $RC/modsecurity.conf /etc/modsecurity/modsecurity.conf
instconf $RC/crs-setup.conf /usr/share/modsecurity-crs/crs-setup.conf
instconf $RC/security2.conf /etc/apache2/mods-available/security2.conf
instdir $RC/rules /etc/modsecurity/rules

chown -R root:root /etc/apache2
chmod 755 /etc/apache2
chmod -R 750 /etc/apache2/bin
chmod -R 750 /etc/apache2/conf
chown -R www-data:www-data /var/www/
find /var/www -type d -exec chmod 775 {} \;

a2enconf security
a2dissite 000-default

a2enmod rewrite security2 evasive headers unique_id
a2dismod -f include imap info userdir autoindex dav dav_fs

mkdir -p /var/cache/modsecurity/uploads
chmod -R 750 /var/cache/modsecurity

ufw allow http
ufw allow https

systemctl reload apache2 && psuccess "Reloaded Apache2" || perror "Failed to reload Apache2"

psuccess "Configured Apache2"
