#!/usr/bin/env bash
# TODO: check for kernel param (?)
# TODO: check if enabled
# TODO: look for an actual set of rules
aa-enforce /etc/apparmor.d/*

