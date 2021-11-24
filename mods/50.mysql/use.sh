ufw deny mysql
instconf $RC/my.cnf /etc/mysql/mysql.cnf
if ! [[ -L /etc/mysql/my.cnf ]];
    instconf $RC/my.cnf /etc/mysql/my.cnf
fi
instconf $RC/mysqld.cnf /etc/mysql/mysql.conf.d/mysqld.cnf
instconf $RC/mysql.cnf /etc/mysql/conf.d/mysql.cnf

systemctl restart mysql && psuccess "Restarted mysql" || perror "Failed to restart mysql"

# TODO: TLS or no?
# TODO: add skip-grant-table check to checklist
# grep -rn "skip-grant-tables" /etc/mysql
