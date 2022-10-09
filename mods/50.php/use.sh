#!/usr/bin/env bash
php_vers=(/etc/php/*)
instconf $RC/php.ini ${php_vers[-1]}/apache2/php.ini

# ===== PHP =====
chown -R root:root /etc/php
chmod 755 /etc/php

