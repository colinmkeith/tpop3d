#
# Makefile: makefile for tpop3d
#
# Copyright (c) 2000 Chris Lightfoot. All Rights Reserved.
#
# $Id$
#
# $Log$
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

CFLAGS  += -g -I/software/include/mysql
LDFLAGS += -g -L/software/lib/mysql
LDLIBS  += -ldl -lpam -lefence -lmysqlclient

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

tpop3d: $(OBJS)
	$(CC) $(LDFLAGS) $(LDLIBS) -o $@ $^

%.o: %.c $(HDRS)
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *~ *.o core tpop3d
