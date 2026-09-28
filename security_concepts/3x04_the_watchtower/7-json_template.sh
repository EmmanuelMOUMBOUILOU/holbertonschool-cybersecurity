#!/bin/bash
echo 'template(name="json_fmt" type="string" string="{\"time\":\"%timestamp%\", \"host\":\"%hostname%\", \"msg\":\"%msg%\"}")' >> /etc/rsyslog.conf