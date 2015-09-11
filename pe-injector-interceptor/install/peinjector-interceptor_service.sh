#!/bin/sh

### BEGIN INIT INFO
# Provides:          peinjector-interceptor
# Required-Start:    $all
# Required-Stop:     $all
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: peinjector-interceptor server
# Description:       Provides peinjector-interceptor server as a service
#
### END INIT INFO

# peinjector-interceptor service script
# Autor: A.A.

# Check root
if [ "$(id -u)" != "0" ]; then
	echo "must be run as root user"
	exit 1
fi

case "$1" in
  start)
    echo "Start peinjector-interceptor server"
    /usr/local/bin/peinjector-interceptor_start.sh
    ;;
  stop)
    echo "Stop peinjector-interceptor server"
    /usr/local/bin/peinjector-interceptor_stop.sh
    ;;
  restart)
    echo "Restart peinjector-interceptor server"
    /usr/local/bin/peinjector-interceptor_stop.sh
    /usr/local/bin/peinjector-interceptor_start.sh
    ;;
  *)
    echo "Usage: /etc/init.d/peinjector-interceptor {start|stop|restart}"
    ;;
esac

exit 0