# FIXME: php versioning?
# FIXME: compare with actual latest php config; different secure configs for different versions?
# FIXME: enable extensions for wordpress (if used) (see arch local /etc/php.ini)
php_vers=(/etc/php/*)
instconf $RC/php.ini ${php_vers[-1]}/apache2/php.ini
