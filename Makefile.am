#
# Makefile.am:
# Automake file for tpop3d.
#
# Copyright (c) 2001 Chris Lightfoot, Mark Longair. All rights reserved.
#
# $Id$
#

sbin_PROGRAMS = tpop3d

tpop3d_SOURCES = auth_mysql.c auth_other.c auth_perl.c auth_pam.c \
                 auth_passwd.c authswitch.c cfgdirectives.c config.c \
                 connection.c listener.c locks.c logging.c mailbox.c \
                 maildir.c mailspool.c main.c md5c.c pidfile.c pop3.c \
                 signals.c stringmap.c strtok_r.c substvars.c \
                 tokenise.c util.c vector.c

noinst_HEADERS = auth_mysql.h auth_other.h auth_perl.h auth_pam.h \
                 auth_passwd.h authswitch.h config.h connection.h \
                 global.h listener.h locks.h mailbox.h md5.h pidfile.h \
                 signals.h stringmap.h tokenise.h vector.h util.h

#tpop3d_LDFLAGS = -L@mysql_root@/lib/mysql

CFLAGS = -Wall -Wpointer-arith -Wstrict-prototypes -g -O2

man_MANS = tpop3d.8 tpop3d.conf.5

SUBDIRS = init.d config

tpop3d.cat: tpop3d.8
	(echo -e ".pl 1100i" ; cat tpop3d.8 ; echo ".pl \n(nlu+10") | groff -Tascii -man > tpop3d.cat

tpop3d.conf.cat: tpop3d.conf.5
	(echo -e ".pl 1100i" ; cat tpop3d.conf.5 ; echo ".pl \n(nlu+10") | groff -Tascii -man > tpop3d.conf.cat

## These need to be distributed along with configure:

EXTRA_DIST = bootstrap \
             CREDITS PORTABILITY CHANGES HACKING TODO FAQ \
             README.auth_mysql README.darwin README.POP-before-SMTP \
             $(man_MANS) \
             tpop3d.cat tpop3d.conf.cat \
             scripts/dotapopfile scripts/nasty scripts/oraclevmail \
             TPOP3D-AuthDriver/AuthDriver.pm TPOP3D-AuthDriver/Changes \
             TPOP3D-AuthDriver/MANIFEST TPOP3D-AuthDriver/Makefile.PL \
             TPOP3D-AuthDriver/test.pl \
             darwin/tpop3d.conf.example \
             darwin/TPOP3D/StartupParameters.plist darwin/TPOP3D/TPOP3D
             
MAINTERCLEANFILES = Makefile.in aclocal.m4 configure configuration.h.in \
                    stamp-h.in
