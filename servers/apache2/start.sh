#!/bin/bash

# Start cupsd
apache2ctl -D FOREGROUND &

# error log
touch /var/log/apache2/error.log
tail -f /var/log/apache2/error.log