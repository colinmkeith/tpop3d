#
# Makefile: makefile for tpop3d
#
# Copyright (c) 2000 Chris Lightfoot. All Rights Reserved.
#
# $Id$
#

VERSION = 1.0
IDLE_TIMEOUT = 30   # seconds before we time out clients

# On machines where gcc is not the default C compiler, you may wish specify
# gcc here, for instance if your vendor's compiler is broken (Solaris
# [cough]).
#CC = gcc

CFLAGS  += -g -DTPOP3D_VERSION='"$(VERSION)"' -DIDLE_TIMEOUT=$(IDLE_TIMEOUT) -Wall
LDFLAGS += -g

# Here you define the location of mailspools; /var/spool/mail is appropriate
# for Linux and many other systems; on BSD, this is typically /var/mail.
MAILSPOOL_DIR = /var/spool/mail
#MAILSPOOL_DIR = /var/mail

CFLAGS += -DMAILSPOOL_DIR='"$(MAILSPOOL_DIR)"'

# On most modern systems, you will want to use PAM (Pluggable Authentication
# Modules) to authenticate Unix (i.e. non-virtual) users. Alternatively, you
# can use auth_passwd, which authenticates users against /etc/passwd or
# /etc/shadow.
CFLAGS += -DAUTH_PAM
#CFLAGS += -DAUTH_PASSWD                            # /etc/passwd
#CFLAGS += -DAUTH_PASSWD -DAUTH_PASSWD_SHADOW       # /etc/shadow

# If you use auth_passwd, you will probably need to link against libcrypt.
#LDLIBS += -lcrypt

# These are the libraries which are needed to get PAM support working. On
# Linux, you need -ldl for dynamic linking support; on other systems (e.g.
# FreeBSD) this is not the case. If you are not using PAM at all, comment
# this out.
LDLIBS += -lpam -ldl

# On some systems you will need to link with additional libraries, or define
# additional flags.
#CFLAGS += -D_REENTRANT     # Solaris
#LDLIBS += -lnsl -lsocket   # Solaris

# If you do not want tpop3d to obtain mailspool locks from PINE and other
# programs which used the Washington University C-Client library, comment out
# the following line (not recommended). At present, Solaris users need to
# switch this off, as it relies on the unsupported flock(2) call.
CFLAGS += -DCCLIENT_LOCKING

# If you do not want tpop3d to do flock(2) locking on mailspools (for instance
# if your system attempts to emulate it using fcntl(2) locking, which would
# cause tpop3d to deadlock), then comment out the following line. Note that
# flock locking is always done on c-client lock files if CCLIENT_LOCKING is
# set, since PINE uses flock. FreeBSD and Solaris users need to comment this
# out.
CFLAGS += -DFLOCK_LOCKING

# For Electric Fence malloc(3) debugging, uncomment the following two lines:
#LDFLAGS += -umalloc -ufree -ucalloc -urealloc
#LDLIBS  += -lefence

# For vmail-sql MySQL support, uncomment the following
#MYSQLROOT = /software
#CFLAGS   += -DAUTH_MYSQL -I$(MYSQLROOT)/include/mysql
#LDFLAGS  += -L$(MYSQLROOT)/lib/mysql
#LDLIBS   += -lmysqlclient

TXTS =  README          \
	PORTABILITY     \
        COPYING         \
        tpop3d.8        \
        tpop3d.cat      \
        init.d/tpop3d

SRCS =  auth_mysql.c	\
        auth_pam.c	\
        auth_passwd.c   \
        authswitch.c	\
        config.c	\
        connection.c	\
        errprintf.c     \
        list.c	        \
        mailspool.c	\
        main.c	        \
        md5c.c	        \
        pop3.c	        \
        stringmap.c	\
	tokenise.c      \
        vector.c

OBJS = $(SRCS:.c=.o)

HDRS =  auth_mysql.h	\
        auth_pam.h	\
        auth_passwd.h   \
        authswitch.h	\
        config.h	\
        connection.h	\
        errprintf.h     \
        global.h	\
        list.h	        \
        mailspool.h	\
        main.h	        \
        md5.h	        \
        stringmap.h	\
	tokenise.h      \
        vector.h        \
        util.h

# If you do not have makedepend, you will need to remove references to depend
# and nodepend below.
tpop3d: depend $(OBJS) Makefile
	$(CC) $(LDFLAGS) $(LDLIBS) -o $@ $(OBJS)

tarball: nodepend
	mkdir tpop3d-$(VERSION)
	for i in $(SUBDIRS) ; do mkdir tpop3d-$(VERSION)/$i ; done
	for i in $(SRCS) $(HDRS) $(TXTS) ; do cp $i tpop3d-$(VERSION)/$i ; done
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
