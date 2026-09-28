#!/bin/bash
echo '*.* @127.0.0.1:514' >> /etc/rsyslog.d/50-default.conf
systemctl restart rsyslog
logger "Test Log Forwarding"