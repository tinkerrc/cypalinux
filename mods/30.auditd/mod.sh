#!/usr/bin/env bash
# FIXME: config syntax errors?
instconf $RC/auditd.conf /etc/audit/auditd.conf
instconf $RC/audit.rules /etc/audit/rules.d/audit.rules
# Force regenerate of main /etc/audit/audit.rules
augenrules --load 
systemctl reload auditd
psuccess "Audit daemon configured"
