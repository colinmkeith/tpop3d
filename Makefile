#
# Makefile: makefile for tpop3d
#
# Copyright (c) 2000 Chris Lightfoot. All Rights Reserved.
#
# $Id$
#

VERSION = 1.1.3
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

# Locking:
# tpop3d supports a number of ways to lock mailspools as compile-time options.
#
# Unfortunately, Unix mailspool locking is arcane and complex (a less
# charitable author would say "broken"). You may have to experiment to get
# this right.
#
# Your choices are:
#
# fcntl(2) locking-- a system locking mechanism supported on all modern
#   systems and which works over NFS.
#
# flock(2) locking-- an older (BSD) locking mechanism which does not work over
#   NFS.
#
# dotfile locking-- an ancient mechanism which uses files ending ".lock" for
#   locking; works (kind of) over NFS.
#
# Switching on several of these means that tpop3d will try to obtain _all_ of
# the locks you specify before accessing a mailspool. If it cannot obtain any
# one of them, it will give up.
#
# In addition, tpop3d can steal locks from PINE and other cooperating
# programs which are based on the C-Client library from Washington University.
# Internally, the C-Client library may use (normally) flock(2) or (on some
# systems) fcntl(2).
#
# It is, unfortunately, not safe simply to turn everything on and hope for the
# best. Some systems, such as modern BSDs, implement flock and fcntl using
# common internals, and on such systems, tpop3d will deadlock while trying to
# obtain both sorts of lock. Some systems, such as Solaris, do not support
# flock(2). Some systems, such as modern Linux distributions, do not use
# dotfile locking at all (and have altered permissions on /var/spool/mail to
# accomodate this).
#
# The following default is probably sensible for most Linux distributions and
# other modern systems:
CFLAGS += -DWITH_FCNTL_LOCKING -DWITH_DOTFILE_LOCKING

# Uncomment this if you have a good reason to want flock(2) locking:
CFLAGS += -DWITH_FLOCK_LOCKING

# On recent RedHat releases and other lockfile-free systems use only this:
#CFLAGS += -DWITH_FCNTL_LOCKING

# If users on your system will use PINE, the Washington University IMAP
# server, or any other software based on the C-Client library, you will want
# this switched on:
CFLAGS += -DWITH_CCLIENT_LOCKING

# On most systems, the C-Client library uses flock(2) locking to lock its own
# lockfiles (really!) but on others where flock(2) is not supported, or where
# the system policy is different (such as new RedHat Linux distributions),
# C-Client will use fcntl(2) locking internally, and you will want to
# uncomment this:
#CFLAGS += -DCCLIENT_USES_FCNTL

# Independent of C-Client-style locking, you can opt for tpop3d not to allow
# users to download or remove the metadata messages which C-Client saves in
# mailspools (these are the ones with subject "DON'T DELETE THIS MESSAGE --
# FOLDER INTERNAL DATA" and an X-IMAP header used to save state associated
# with IMAP UIDs). This is harmless if your users do not use PINE, and
# probably desirable if they do.
CFLAGS += -DIGNORE_CCLIENT_METADATA

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
        CREDITS         \
        TODO            \
        tpop3d.8        \
        tpop3d.cat      \
        init.d/tpop3d

SUBDIRS = init.d

SRCS =  auth_mysql.c	\
        auth_pam.c	\
        auth_passwd.c   \
        authswitch.c	\
        config.c	\
        connection.c	\
        errprintf.c     \
        list.c	        \
        locks.c         \
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
        locks.h         \
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
	for i in $(SUBDIRS) ; do mkdir tpop3d-$(VERSION)/$$i ; done
	for i in Makefile $(SRCS) $(HDRS) $(TXTS) ; do cp $$i tpop3d-$(VERSION)/$$i ; done
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
