#
# Makefile: makefile for tpop3d
#
# Copyright (c) 2000 Chris Lightfoot. All Rights Reserved.
#
# $Id$
#
# $Log$
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

VERSION = 0.4

MYSQLROOT = /software
# MYSQLROOT = /usr

CFLAGS  += -g -I$(MYSQLROOT)/include/mysql -DTPOP3D_VERSION='"$(VERSION)"' -Wall
LDFLAGS += -g -L$(MYSQLROOT)/lib/mysql
LDLIBS  += -ldl -lpam -lefence -lmysqlclient

TXTS =  README          \
        COPYING

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
        vector.h

tpop3d: $(OBJS) depend Makefile
	$(CC) $(LDFLAGS) $(LDLIBS) -o $@ $(OBJS)

tarball: nodepend
	mkdir tpop3d-$(VERSION)
	cp $(SRCS) $(HDRS) $(TXTS) Makefile tpop3d-$(VERSION)
	tar cvzf tpop3d-$(VERSION).tar.gz tpop3d-$(VERSION)
	rm -rf tpop3d-$(VERSION)
	mv tpop3d-$(VERSION).tar.gz ..

checkin:
	ci -l $(SRCS) $(HDRS) $(TXTS) Makefile

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean: nodepend
	rm -f *~ *.o core tpop3d depend TAGS

tags :
	etags *.c *.h

depend:
	makedepend -- $(CFLAGS) -- $(SRCS)
	touch depend

nodepend:
	head -`grep -n "^# DO NOT DELETE" < Makefile | awk -F: '{print $$1;}'` < Makefile > Makefile.tmp # ugly; is there a better way to do this?
	mv Makefile.tmp Makefile
	rm -f depend
 
# DO NOT DELETE
