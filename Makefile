#
# Makefile: makefile for tpop3d
#
# Copyright (c) 2000 Chris Lightfoot. All Rights Reserved.
#
# $Id$
#
# $Log$
# Revision 1.10  2000/10/28 14:57:04  chris
# Added man page, conditional auth_mysql compilation.
#
# Revision 1.9  2000/10/18 22:27:14  chris
# Minor changes.
#
# Revision 1.8  2000/10/18 22:21:23  chris
# Minor changes.
#
# Revision 1.7  2000/10/18 21:34:12  chris
# Changes due to Mark Longair.
#
# Revision 1.6  2000/10/10 00:05:36  chris
# Various changes.
#
# Revision 1.5  2000/10/09 23:24:34  chris
# Minor changess.
#
# Revision 1.4  2000/10/09 23:19:07  chris
# Makefile now works and stuff.
#
# Revision 1.3  2000/10/09 22:47:31  chris
# Added .h dependencies.
#
# Revision 1.2  2000/10/02 18:20:19  chris
# Minor changes.
#
# Revision 1.1  2000/09/18 23:43:38  chris
# Initial revision
#
#

VERSION = 0.6
IDLE_TIMEOUT = 30   # seconds before we time out clients

CFLAGS  += -g -DTPOP3D_VERSION='"$(VERSION)"' -DIDLE_TIMEOUT=$(IDLE_TIMEOUT) -Wall
LDFLAGS += -g
LDLIBS  += -ldl -lpam

# For Electric Fence malloc(3) debugging, uncomment the following two lines:
# LDFLAGS += -umalloc -ufree -ucalloc -urealloc
# LDLIBS  += -lefence

# For vmail-sql MySQL support, uncomment the following
#MYSQLROOT = /usr/local
#CFLAGS   += -DAUTH_MYSQL -I$(MYSQLROOT)/include/mysql
#LDFLAGS  += -L$(MYSQLROOT)/lib/mysql
#LDLIBS   += -lmysqlclient

TXTS =  README          \
        COPYING         \
        tpop3d.8        \
        tpop3d.cat

SRCS =  auth_mysql.c	\
        auth_pam.c	\
        authswitch.c	\
        config.c	\
        connection.c	\
        list.c	        \
        mailspool.c	\
        main.c	        \
        md5c.c	        \
        pop3.c	        \
        stringmap.c	\
        vector.c

OBJS = $(SRCS:.c=.o)

HDRS =  auth_mysql.h	\
        auth_pam.h	\
        authswitch.h	\
        config.h	\
        connection.h	\
        global.h	\
        list.h	        \
        mailspool.h	\
        main.h	        \
        md5.h	        \
        stringmap.h	\
        vector.h        \
        util.h

tpop3d: depend $(OBJS) Makefile
	$(CC) $(LDFLAGS) $(LDLIBS) -o $@ $(OBJS)

tarball: nodepend
	mkdir tpop3d-$(VERSION)
	cp $(SRCS) $(HDRS) $(TXTS) Makefile tpop3d-$(VERSION)
	tar cvzf tpop3d-$(VERSION).tar.gz tpop3d-$(VERSION)
	rm -rf tpop3d-$(VERSION)
	mv tpop3d-$(VERSION).tar.gz ..

checkin:
	ci -l $(SRCS) $(HDRS) $(TXTS) Makefile

%.o: %.c Makefile
	$(CC) $(CFLAGS) -c -o $@ $<

clean: nodepend
	rm -f *~ *.o core tpop3d depend TAGS

tags :
	etags *.c *.h

depend:
	makedepend -- $(CFLAGS) -- $(SRCS)
	touch depend

nodepend:
	makedepend -- --
	rm -f depend
 
# DO NOT DELETE
