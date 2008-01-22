#!/bin/sh
#
# tpop3d:
# Init script for starting/stopping tpop3d.
#
# Copyright (c) 2001 Chris Lightfoot.
#  Portability enhanced by Chris Elsworth, July 2001
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.


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

