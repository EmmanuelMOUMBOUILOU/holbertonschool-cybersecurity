#!/bin/bash
cp /etc/rsyslog.conf /etc/rsyslog.conf.bak
sed -i 's/^#module(load="imudp")/module(load="imudp")/; s/^#input(type="imudp" port="514")/input(type="imudp" port="514")/; s/^#module(load="imtcp")/module(load="imtcp")/; s/^#input(type="imtcp" port="514")/input(type="imtcp" port="514")/' /etc/rsyslog.conf
systemctl restart rsyslog