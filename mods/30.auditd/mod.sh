# TODO: move into pkglist
# TODO: test
# TODO: auditd.conf

instconf $RC/audit.rules /etc/audit/rules.d/audit.rules
# Force regenerate of main /etc/audit/audit.rules
augenrules --load 
systemctl reload auditd
psuccess "Audit daemon configured"
