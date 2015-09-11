#!/bin/sh

# peinjector start script
# Autor: A.A.

# Check root
if [ "$(id -u)" != "0" ]; then
	echo "must be run as root user"
	exit 1
fi

# set Log files and working dir
LOG_FILE=/var/log/peinjector/injector.log
ERROR_FILE=/var/log/peinjector/injector.err
WORKING_DIR=/etc/peinjector

# start server
cd $WORKING_DIR
(/usr/bin/peinjector --server >> $LOG_FILE 2>> $ERROR_FILE </dev/null) &

exit 0