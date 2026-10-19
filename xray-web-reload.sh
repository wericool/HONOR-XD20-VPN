#!/bin/sh
# Authentication changes must return their CGI response before httpd restarts.
sleep 2
exec sh /data/xray-test/xray-web.sh restart
