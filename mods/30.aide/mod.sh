aide -i # initialize database
add-crontab "0 5 * * * /usr/bin/aide.wrapper --config /etc/aide/aide.conf --check"
