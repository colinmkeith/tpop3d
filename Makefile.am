#
# Makefile.am:
# Automake file for tpop3d.
#
# Copyright (c) 2001 Chris Lightfoot, Mark Longair. All rights reserved.
#
# $Id$
#

sbin_PROGRAMS = tpop3d

tpop3d_SOURCES = auth_mysql.c auth_pgsql.c auth_ldap.c auth_other.c \
                 auth_perl.c auth_pam.c auth_passwd.c auth_flatfile.c \
                 authswitch.c buffer.c cfgdirectives.c config.c connection.c \
                 ioabs_tcp.c ioabs_tls.c listener.c locks.c logging.c \
                 mailbox.c maildir.c mailspool.c main.c md5c.c netloop.c \
                 password.c pidfile.c pop3.c signals.c stringmap.c strtok_r.c \
                 substvars.c tls.c tokenise.c util.c vector.c

noinst_HEADERS = auth_mysql.h auth_ldap.h auth_other.h auth_perl.h auth_pam.h \
                 auth_passwd.h auth_flatfile.h authswitch.h buffer.h config.h \
                 connection.h listener.h locks.h mailbox.h md5.h password.h \
                 pidfile.h signals.h stringmap.h tls.h tokenise.h vector.h \
                 util.h

CFLAGS += -Wall -g -O2 -DCONFIG_DIR='"@sysconfdir@"' # -Wstrict-prototypes

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
             tpop3d.cat tpop3d.conf.cat tpop3d.conf.sample \
             scripts/dotapopfile scripts/nasty scripts/oraclevmail \
             scripts/ruby-sample scripts/relaydbm scripts/authdbm \
             scripts/tpop3dtraffic \
             TPOP3D-AuthDriver/AuthDriver.pm TPOP3D-AuthDriver/Changes \
             TPOP3D-AuthDriver/MANIFEST TPOP3D-AuthDriver/Makefile.PL \
             TPOP3D-AuthDriver/test.pl \
             darwin/tpop3d.conf.example \
             darwin/TPOP3D/StartupParameters.plist darwin/TPOP3D/TPOP3D \
             config/check_lib2.m4
             
MAINTERCLEANFILES = Makefile.in aclocal.m4 configure configuration.h.in \
                    stamp-h.in

ACLOCAL = aclocal -I @ac_aux_dir@

