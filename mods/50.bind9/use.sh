#!/usr/bin/env bash
sed -i 's/^.*version\s+".*";.*/version none;/' /etc/bind/named.conf.options
sed -i 's/^.*allow-transfer.*;.*/allow-transfer {none;};/' /etc/bind/named.conf.options
chmod -R o-rwx /etc/bind
