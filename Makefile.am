sbin_PROGRAMS = tpop3d

tpop3d_SOURCES = auth_mysql.c \
                 auth_pam.c \
                 auth_passwd.c \
                 authswitch.c \
                 cfgdirectives.c \
                 config.c \
                 connection.c \
                 errprintf.c \
                 list.c	\
                 listener.c \
                 locks.c \
                 mailspool.c \
                 main.c \
                 md5c.c \
                 pidfile.c \
                 pop3.c	\
                 signals.c \
                 stringmap.c \
                 tokenise.c \
                 util.c \
                 vector.c

noinst_HEADERS = auth_mysql.h \
                 auth_pam.h \
                 auth_passwd.h \
                 authswitch.h \
                 config.h \
                 connection.h \
                 errprintf.h \
                 global.h \
                 list.h \
                 listener.h \
                 locks.h \
                 mailspool.h \
                 main.h \
                 md5.h \
                 pidfile.h \
                 signals.h \
                 stringmap.h \
                 tokenise.h \
                 vector.h \
                 util.h

tpop3d_LDFLAGS = -L@mysql_root@/lib/mysql

CFLAGS = -Wall -g

man_MANS = tpop3d.8

SUBDIRS = init.d config

## These need to be distributed along with configure:

EXTRA_DIST = bootstrap \
             mysql_crypt.patch \
             CREDITS \
             PORTABILITY \
             $(man_MANS)

MAINTERCLEANFILES = Makefile.in aclocal.m4 configure configuration.h.in \
                    stamp-h.in
