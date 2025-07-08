#!/bin/bash

# Start cupsd
cupsd -f &

# error log
touch /var/log/cups/error_log
tail -f /var/log/cups/error_log