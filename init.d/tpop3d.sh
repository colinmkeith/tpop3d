#!/bin/sh
#
# tpop3d:
# Init script for starting/stopping tpop3d.
#
# Copyright (c) 2001 Chris Lightfoot. All rights reserved.
#  Portability enhanced by Chris Elsworth, July 2001
#

DAEMON=/sbin/tpop3d

[ -f $DAEMON ] || exit 0

# See how we were called.
case "$1" in
  start)
        # Start daemons.
        $DAEMON -f /etc/tpop3d.conf -p /var/run/tpop3d.pid \
		&& echo -n " tpop3d"
        ;;
  stop)
        # Stop daemons.
	[ -r /var/run/httpd.pid ] && kill `cat /var/run/tpop3d.pid` \
		&& echo -n " tpop3d"
        ;;
  restart)
	$0 stop
	$0 start
	;;
  reload)
  	[ -r /var/run/httpd.pid ] && kill -HUP `cat /var/run/tpop3d.pid`
        ;;
  *)
        echo "Usage: `basename $0` {start|stop|restart|reload}"
        exit 1
esac

exit 0

