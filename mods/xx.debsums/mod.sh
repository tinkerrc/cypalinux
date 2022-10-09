#!/usr/bin/env bash
pinfo "Verifying package integrity (including config files)"
pfino "Starting in 3 seconds..."
sleep 3
debsums -a
