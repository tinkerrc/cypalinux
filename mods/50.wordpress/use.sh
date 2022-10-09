#!/usr/bin/env bash
instconf $RC/wordpress.conf /etc/apache2/sites-available/wordpress.conf
a2ensite wordpress

# separate wordpress from apache2
mkdir -p /var/www/html
ln -s /usr/share/wordpress /var/www/html/wordpress

chown -R www-data /usr/share/wordpress
find /usr/share/wordpress -type d -exec chmod 775 {} \;
