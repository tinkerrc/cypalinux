#!/usr/bin/env bash
ufw enable http
ufw enable https
chown -R www-data:www-data /var/www/
find /var/www -type d -exec chmod 775 {} \;
