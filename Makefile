#
# Makefile: makefile for tpop3d
#
# Copyright (c) 2000 Chris Lightfoot. All Rights Reserved.
#
# $Id$
#
# $Log$
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

tpop3d: auth_mysql.o auth_pam.o authswitch.o config.o connection.o list.o mailspool.o main.o md5c.c pop3.o stringmap.o vector.o
	$(CC) $(LDFLAGS) $(LDLIBS) -o $@ $^

clean:
	rm *~
	rm *.o
	rm core
