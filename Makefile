#
# Makefile: makefile for tpop3d
#
# Copyright (c) 2000 Chris Lightfoot. All Rights Reserved.
#
# $Id$
#
# $Log$
# Revision 1.1  2000/09/18 23:43:38  chris
# Initial revision
#
#

CFLAGS += -g

tpop3d: auth_pam.o authswitch.o connection.o list.o main.o pop3.o vector.o Makefile
	$(CC) -o $@ connection.o list.o main.o vector.o
