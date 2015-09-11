#!/bin/sh

# peinjector-interceptor start script
# Autor: A.A.

# Check root
if [ "$(id -u)" != "0" ]; then
	echo "must be run as root user"
	exit 1
fi

# set Log files and working dir
LOG_FILE=/var/log/peinjector-interceptor/interceptor.log
ERROR_FILE=/var/log/peinjector-interceptor/interceptor.err
WORKING_DIR=/etc/peinjector-interceptor

# start server
cd $WORKING_DIR
((python2 ./peinjector_interceptor.py) >> $LOG_FILE 2>> $ERROR_FILE </dev/null) &

exit 0