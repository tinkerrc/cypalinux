#!/usr/bin/env bash
aideinit
add-crontab "0 5 * * * /usr/bin/aide.wrapper --config /etc/aide/aide.conf --check"
