#!/usr/bin/env bash
apt install software-properties-common
add-apt-repository --yes --update ppa:ansible/ansible
# TODO: implement https://github.com/dev-sec/ansible-collection-hardening
# TODO: implement ansible hardening for other services (nginx, mysql, etc), convert to regular module when done (pkgs)
