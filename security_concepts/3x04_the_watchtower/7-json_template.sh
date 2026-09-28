#!/bin/bash
printf '%s\n' 'template(name="json_fmt" type="string" string="{\"time\":\"%timestamp%\", \"host\":\"%hostname%\", \"msg\":\"%msg%\"}")' >> /etc/rsyslog.conf