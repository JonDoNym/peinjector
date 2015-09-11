#!/bin/sh

### BEGIN INIT INFO
# Provides:          peinjector-control
# Required-Start:    $all
# Required-Stop:     $all
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: peinjector-control server
# Description:       Provides peinjector-control server as a service
#
### END INIT INFO

# peinjector-control service script
# Autor: A.A.

# Check root
if [ "$(id -u)" != "0" ]; then
	echo "must be run as root user"
	exit 1
fi

case "$1" in
  start)
    echo "Start peinjector-control server"
    /usr/local/bin/peinjector-control_start.sh
    ;;
  stop)
    echo "Stop peinjector-control server"
    /usr/local/bin/peinjector-control_stop.sh
    ;;
  restart)
    echo "Restart peinjector-control server"
    /usr/local/bin/peinjector-control_stop.sh
    /usr/local/bin/peinjector-control_start.sh
    ;;
  *)
    echo "Usage: /etc/init.d/peinjector-control {start|stop|restart}"
    ;;
esac

exit 0