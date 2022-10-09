#!/usr/bin/env bash
apt install software-properties-common
add-apt-repository --yes --update ppa:ansible/ansible # ansible is a dep
apt install ssg-base ssg-debderived ssg-debian ssg-nondebian ssg-applications
# TODO: implement scap scan
# https://www.open-scap.org/getting-started/
