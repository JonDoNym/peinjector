#!/bin/sh

### BEGIN INIT INFO
# Provides:          peinjector
# Required-Start:    $all
# Required-Stop:     $all
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: peinjector server
# Description:       Provides peinjector server as a service
#
### END INIT INFO

# peinjector service script
# Autor: A.A.

# Check root
if [ "$(id -u)" != "0" ]; then
	echo "must be run as root user"
	exit 1
fi

case "$1" in
  start)
    echo "Start peinjector server"
    /usr/local/bin/peinjector_start.sh
    ;;
  stop)
    echo "Stop peinjector server"
    /usr/local/bin/peinjector_stop.sh
    ;;
  restart)
    echo "Restart peinjector server"
    /usr/local/bin/peinjector_stop.sh
    /usr/local/bin/peinjector_start.sh
    ;;
  *)
    echo "Usage: /etc/init.d/peinjector {start|stop|restart}"
    ;;
esac

exit 0