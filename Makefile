#
# Makefile: makefile for tpop3d
#
# Copyright (c) 2000 Chris Lightfoot. All Rights Reserved.
#
# $Id$
#

VERSION = 1.2.3

# On machines where gcc is not the default C compiler, you may wish to specify
# gcc here, for instance if your vendor's compiler is broken (Solaris
# [cough]).
#CC = gcc

CFLAGS  += -g -DTPOP3D_VERSION='"$(VERSION)"' -Wall
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

# If you want to be able to authenticate users in virtual domains against a
# MySQL database, switch these on. This uses the vmail-sql authentication
# schema (see http://www.ex-parrot.com/~chris/vmail-sql), but could easily
# be adapted to use another. For an example, apply mysql_crypt.patch, which
# modifies auth_mysql to use passwords hashed with crypt(3) rather than MD5.
#MYSQLROOT = /software
#CFLAGS   += -DAUTH_MYSQL -I$(MYSQLROOT)/include/mysql
#LDFLAGS  += -L$(MYSQLROOT)/lib/mysql
#LDLIBS   += -lmysqlclient

# Some people may find that users whose POP3 clients report errors from the
# server verbatim complain at the wording of some server responses. If you are
# in this position, you can uncomment the following line (not recommended; in
# my view, this is a technical solution to a social problem, and anyway users
# should get used to their computers being rude to them).
#CFLAGS += -DNO_SNIDE_COMMENTS

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
# systems) fcntl(2). tpop3d does not establish C-Client locks itself. If this
# is confusing, read the C-Client source; however, I do not guarantee that
# this will enlighten you.
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
#CFLAGS += -DWITH_FLOCK_LOCKING

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

TXTS =  README          \
	PORTABILITY     \
        CHANGES         \
        COPYING         \
        CREDITS         \
        TODO            \
        mysql_crypt.patch   \
        tpop3d.8        \
        tpop3d.cat      \
        init.d/tpop3d   \
        init.d/initscript_wait-for-mysqld.patch

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

tpop3d.cat: tpop3d.8 Makefile
	(echo -e ".pl 1100i" ; cat tpop3d.8 ; echo ".pl \n(nlu+10") | groff -Tascii -man > tpop3d.cat

tarball: nodepend $(SRCS) $(HDRS) $(TXTS)
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
	rm -f *~ *.o core tpop3d depend TAGS *.bak

tags :
	etags *.c *.h

depend:
	makedepend -- $(CFLAGS) -- $(SRCS)
	touch depend

nodepend:
	makedepend -- --
	rm -f depend
 
# DO NOT DELETE

auth_pam.o: /usr/include/sys/types.h /usr/include/features.h
auth_pam.o: /usr/include/sys/cdefs.h /usr/include/gnu/stubs.h
auth_pam.o: /usr/include/bits/types.h
auth_pam.o: /usr/lib/gcc-lib/i386-redhat-linux/egcs-2.91.66/include/stddef.h
auth_pam.o: /usr/include/time.h /usr/include/endian.h
auth_pam.o: /usr/include/bits/endian.h /usr/include/sys/select.h
auth_pam.o: /usr/include/bits/select.h /usr/include/bits/sigset.h
auth_pam.o: /usr/include/sys/sysmacros.h /usr/include/grp.h
auth_pam.o: /usr/include/stdio.h /usr/include/pwd.h /usr/include/stdlib.h
auth_pam.o: /usr/include/alloca.h /usr/include/string.h /usr/include/syslog.h
auth_pam.o: /usr/include/sys/syslog.h
auth_pam.o: /usr/lib/gcc-lib/i386-redhat-linux/egcs-2.91.66/include/stdarg.h
auth_pam.o: /usr/include/security/pam_appl.h
auth_pam.o: /usr/include/security/_pam_types.h /usr/include/locale.h
auth_pam.o: /usr/include/security/pam_modules.h
auth_pam.o: /usr/include/security/_pam_compat.h auth_pam.h authswitch.h
auth_pam.o: stringmap.h vector.h util.h
authswitch.o: /usr/include/stdio.h /usr/include/stdlib.h
authswitch.o: /usr/include/features.h /usr/include/sys/cdefs.h
authswitch.o: /usr/include/gnu/stubs.h
authswitch.o: /usr/lib/gcc-lib/i386-redhat-linux/egcs-2.91.66/include/stddef.h
authswitch.o: /usr/include/sys/types.h /usr/include/bits/types.h
authswitch.o: /usr/include/time.h /usr/include/endian.h
authswitch.o: /usr/include/bits/endian.h /usr/include/sys/select.h
authswitch.o: /usr/include/bits/select.h /usr/include/bits/sigset.h
authswitch.o: /usr/include/sys/sysmacros.h /usr/include/alloca.h
authswitch.o: /usr/include/string.h /usr/include/syslog.h
authswitch.o: /usr/include/sys/syslog.h
authswitch.o: /usr/lib/gcc-lib/i386-redhat-linux/egcs-2.91.66/include/stdarg.h
authswitch.o: /usr/include/unistd.h /usr/include/bits/posix_opt.h
authswitch.o: /usr/include/bits/confname.h /usr/include/getopt.h auth_pam.h
authswitch.o: authswitch.h stringmap.h vector.h util.h
config.o: /usr/include/errno.h /usr/include/features.h
config.o: /usr/include/sys/cdefs.h /usr/include/gnu/stubs.h
config.o: /usr/include/bits/errno.h /usr/include/linux/errno.h
config.o: /usr/include/asm/errno.h /usr/include/stdio.h /usr/include/stdlib.h
config.o: /usr/lib/gcc-lib/i386-redhat-linux/egcs-2.91.66/include/stddef.h
config.o: /usr/include/sys/types.h /usr/include/bits/types.h
config.o: /usr/include/time.h /usr/include/endian.h
config.o: /usr/include/bits/endian.h /usr/include/sys/select.h
config.o: /usr/include/bits/select.h /usr/include/bits/sigset.h
config.o: /usr/include/sys/sysmacros.h /usr/include/alloca.h
config.o: /usr/include/string.h /usr/include/syslog.h
config.o: /usr/include/sys/syslog.h
config.o: /usr/lib/gcc-lib/i386-redhat-linux/egcs-2.91.66/include/stdarg.h
config.o: config.h stringmap.h vector.h util.h
connection.o: /usr/include/errno.h /usr/include/features.h
connection.o: /usr/include/sys/cdefs.h /usr/include/gnu/stubs.h
connection.o: /usr/include/bits/errno.h /usr/include/linux/errno.h
connection.o: /usr/include/asm/errno.h /usr/include/fcntl.h
connection.o: /usr/include/bits/fcntl.h /usr/include/sys/types.h
connection.o: /usr/include/bits/types.h
connection.o: /usr/lib/gcc-lib/i386-redhat-linux/egcs-2.91.66/include/stddef.h
connection.o: /usr/include/time.h /usr/include/endian.h
connection.o: /usr/include/bits/endian.h /usr/include/sys/select.h
connection.o: /usr/include/bits/select.h /usr/include/bits/sigset.h
connection.o: /usr/include/sys/sysmacros.h /usr/include/pwd.h
connection.o: /usr/include/stdio.h /usr/include/stdlib.h
connection.o: /usr/include/alloca.h /usr/include/string.h
connection.o: /usr/include/syslog.h /usr/include/sys/syslog.h
connection.o: /usr/lib/gcc-lib/i386-redhat-linux/egcs-2.91.66/include/stdarg.h
connection.o: /usr/include/unistd.h /usr/include/bits/posix_opt.h
connection.o: /usr/include/bits/confname.h /usr/include/getopt.h
connection.o: /usr/include/netinet/in.h /usr/include/limits.h
connection.o: /usr/include/bits/posix1_lim.h /usr/include/bits/local_lim.h
connection.o: /usr/include/linux/limits.h /usr/include/bits/posix2_lim.h
connection.o: /usr/include/stdint.h /usr/include/bits/wordsize.h
connection.o: /usr/include/bits/socket.h /usr/include/bits/sockaddr.h
connection.o: /usr/include/asm/socket.h /usr/include/asm/sockios.h
connection.o: /usr/include/bits/in.h /usr/include/bits/byteswap.h
connection.o: /usr/include/arpa/inet.h /usr/include/sys/socket.h
connection.o: /usr/include/sys/utsname.h /usr/include/bits/utsname.h
connection.o: connection.h authswitch.h mailspool.h /usr/include/sys/stat.h
connection.o: /usr/include/bits/stat.h vector.h tokenise.h util.h
errprintf.o: /usr/include/errno.h /usr/include/features.h
errprintf.o: /usr/include/sys/cdefs.h /usr/include/gnu/stubs.h
errprintf.o: /usr/include/bits/errno.h /usr/include/linux/errno.h
errprintf.o: /usr/include/asm/errno.h
errprintf.o: /usr/lib/gcc-lib/i386-redhat-linux/egcs-2.91.66/include/stdarg.h
errprintf.o: /usr/include/stdio.h /usr/include/stdlib.h
errprintf.o: /usr/lib/gcc-lib/i386-redhat-linux/egcs-2.91.66/include/stddef.h
errprintf.o: /usr/include/sys/types.h /usr/include/bits/types.h
errprintf.o: /usr/include/time.h /usr/include/endian.h
errprintf.o: /usr/include/bits/endian.h /usr/include/sys/select.h
errprintf.o: /usr/include/bits/select.h /usr/include/bits/sigset.h
errprintf.o: /usr/include/sys/sysmacros.h /usr/include/alloca.h
errprintf.o: /usr/include/string.h
list.o: /usr/include/stdlib.h /usr/include/features.h
list.o: /usr/include/sys/cdefs.h /usr/include/gnu/stubs.h
list.o: /usr/lib/gcc-lib/i386-redhat-linux/egcs-2.91.66/include/stddef.h
list.o: /usr/include/sys/types.h /usr/include/bits/types.h
list.o: /usr/include/time.h /usr/include/endian.h /usr/include/bits/endian.h
list.o: /usr/include/sys/select.h /usr/include/bits/select.h
list.o: /usr/include/bits/sigset.h /usr/include/sys/sysmacros.h
list.o: /usr/include/alloca.h /usr/include/string.h list.h vector.h util.h
locks.o: locks.h /usr/include/errno.h /usr/include/features.h
locks.o: /usr/include/sys/cdefs.h /usr/include/gnu/stubs.h
locks.o: /usr/include/bits/errno.h /usr/include/linux/errno.h
locks.o: /usr/include/asm/errno.h /usr/include/fcntl.h
locks.o: /usr/include/bits/fcntl.h /usr/include/sys/types.h
locks.o: /usr/include/bits/types.h
locks.o: /usr/lib/gcc-lib/i386-redhat-linux/egcs-2.91.66/include/stddef.h
locks.o: /usr/include/time.h /usr/include/endian.h /usr/include/bits/endian.h
locks.o: /usr/include/sys/select.h /usr/include/bits/select.h
locks.o: /usr/include/bits/sigset.h /usr/include/sys/sysmacros.h
locks.o: /usr/include/signal.h /usr/include/bits/signum.h
locks.o: /usr/include/bits/siginfo.h /usr/include/bits/sigaction.h
locks.o: /usr/include/bits/sigcontext.h /usr/include/asm/sigcontext.h
locks.o: /usr/include/bits/sigstack.h /usr/include/stdio.h
locks.o: /usr/include/stdlib.h /usr/include/alloca.h /usr/include/string.h
locks.o: /usr/include/syslog.h /usr/include/sys/syslog.h
locks.o: /usr/lib/gcc-lib/i386-redhat-linux/egcs-2.91.66/include/stdarg.h
locks.o: /usr/include/unistd.h /usr/include/bits/posix_opt.h
locks.o: /usr/include/bits/confname.h /usr/include/getopt.h
locks.o: /usr/include/sys/file.h /usr/include/sys/stat.h
locks.o: /usr/include/bits/stat.h /usr/include/sys/utsname.h
locks.o: /usr/include/bits/utsname.h util.h
mailspool.o: /usr/include/errno.h /usr/include/features.h
mailspool.o: /usr/include/sys/cdefs.h /usr/include/gnu/stubs.h
mailspool.o: /usr/include/bits/errno.h /usr/include/linux/errno.h
mailspool.o: /usr/include/asm/errno.h /usr/include/fcntl.h
mailspool.o: /usr/include/bits/fcntl.h /usr/include/sys/types.h
mailspool.o: /usr/include/bits/types.h
mailspool.o: /usr/lib/gcc-lib/i386-redhat-linux/egcs-2.91.66/include/stddef.h
mailspool.o: /usr/include/time.h /usr/include/endian.h
mailspool.o: /usr/include/bits/endian.h /usr/include/sys/select.h
mailspool.o: /usr/include/bits/select.h /usr/include/bits/sigset.h
mailspool.o: /usr/include/sys/sysmacros.h /usr/include/signal.h
mailspool.o: /usr/include/bits/signum.h /usr/include/bits/siginfo.h
mailspool.o: /usr/include/bits/sigaction.h /usr/include/bits/sigcontext.h
mailspool.o: /usr/include/asm/sigcontext.h /usr/include/bits/sigstack.h
mailspool.o: /usr/include/stdio.h /usr/include/string.h /usr/include/syslog.h
mailspool.o: /usr/include/sys/syslog.h
mailspool.o: /usr/lib/gcc-lib/i386-redhat-linux/egcs-2.91.66/include/stdarg.h
mailspool.o: /usr/include/unistd.h /usr/include/bits/posix_opt.h
mailspool.o: /usr/include/bits/confname.h /usr/include/getopt.h
mailspool.o: /usr/include/sys/file.h /usr/include/sys/mman.h
mailspool.o: /usr/include/bits/mman.h /usr/include/sys/stat.h
mailspool.o: /usr/include/bits/stat.h /usr/include/sys/time.h
mailspool.o: /usr/include/bits/time.h /usr/include/sys/utsname.h
mailspool.o: /usr/include/bits/utsname.h connection.h /usr/include/pwd.h
mailspool.o: /usr/include/netinet/in.h /usr/include/limits.h
mailspool.o: /usr/include/bits/posix1_lim.h /usr/include/bits/local_lim.h
mailspool.o: /usr/include/linux/limits.h /usr/include/bits/posix2_lim.h
mailspool.o: /usr/include/stdint.h /usr/include/bits/wordsize.h
mailspool.o: /usr/include/bits/socket.h /usr/include/bits/sockaddr.h
mailspool.o: /usr/include/asm/socket.h /usr/include/asm/sockios.h
mailspool.o: /usr/include/bits/in.h /usr/include/bits/byteswap.h
mailspool.o: /usr/include/sys/socket.h authswitch.h /usr/include/stdlib.h
mailspool.o: /usr/include/alloca.h mailspool.h vector.h tokenise.h locks.h
mailspool.o: md5.h global.h util.h
main.o: /usr/include/errno.h /usr/include/features.h /usr/include/sys/cdefs.h
main.o: /usr/include/gnu/stubs.h /usr/include/bits/errno.h
main.o: /usr/include/linux/errno.h /usr/include/asm/errno.h
main.o: /usr/include/fcntl.h /usr/include/bits/fcntl.h
main.o: /usr/include/sys/types.h /usr/include/bits/types.h
main.o: /usr/lib/gcc-lib/i386-redhat-linux/egcs-2.91.66/include/stddef.h
main.o: /usr/include/time.h /usr/include/endian.h /usr/include/bits/endian.h
main.o: /usr/include/sys/select.h /usr/include/bits/select.h
main.o: /usr/include/bits/sigset.h /usr/include/sys/sysmacros.h
main.o: /usr/include/netdb.h /usr/include/rpc/netdb.h
main.o: /usr/include/sys/socket.h /usr/include/bits/socket.h
main.o: /usr/include/limits.h /usr/include/bits/posix1_lim.h
main.o: /usr/include/bits/local_lim.h /usr/include/linux/limits.h
main.o: /usr/include/bits/posix2_lim.h /usr/include/bits/sockaddr.h
main.o: /usr/include/asm/socket.h /usr/include/asm/sockios.h
main.o: /usr/include/signal.h /usr/include/bits/signum.h
main.o: /usr/include/bits/siginfo.h /usr/include/bits/sigaction.h
main.o: /usr/include/bits/sigcontext.h /usr/include/asm/sigcontext.h
main.o: /usr/include/bits/sigstack.h
main.o: /usr/lib/gcc-lib/i386-redhat-linux/egcs-2.91.66/include/stdarg.h
main.o: /usr/include/stdio.h /usr/include/string.h /usr/include/syslog.h
main.o: /usr/include/sys/syslog.h /usr/include/unistd.h
main.o: /usr/include/bits/posix_opt.h /usr/include/bits/confname.h
main.o: /usr/include/getopt.h /usr/include/netinet/in.h /usr/include/stdint.h
main.o: /usr/include/bits/wordsize.h /usr/include/bits/in.h
main.o: /usr/include/bits/byteswap.h /usr/include/arpa/inet.h
main.o: /usr/include/sys/time.h /usr/include/bits/time.h
main.o: /usr/include/sys/utsname.h /usr/include/bits/utsname.h
main.o: /usr/include/sys/wait.h /usr/include/bits/waitflags.h
main.o: /usr/include/bits/waitstatus.h config.h stringmap.h vector.h
main.o: connection.h /usr/include/pwd.h authswitch.h /usr/include/stdlib.h
main.o: /usr/include/alloca.h mailspool.h /usr/include/sys/stat.h
main.o: /usr/include/bits/stat.h tokenise.h errprintf.h list.h util.h
md5c.o: md5.h global.h /usr/include/limits.h /usr/include/features.h
md5c.o: /usr/include/sys/cdefs.h /usr/include/gnu/stubs.h
md5c.o: /usr/include/bits/posix1_lim.h /usr/include/bits/local_lim.h
md5c.o: /usr/include/linux/limits.h /usr/include/bits/posix2_lim.h
md5c.o: /usr/include/memory.h /usr/include/string.h
md5c.o: /usr/lib/gcc-lib/i386-redhat-linux/egcs-2.91.66/include/stddef.h
pop3.o: /usr/include/stdio.h /usr/include/stdlib.h /usr/include/features.h
pop3.o: /usr/include/sys/cdefs.h /usr/include/gnu/stubs.h
pop3.o: /usr/lib/gcc-lib/i386-redhat-linux/egcs-2.91.66/include/stddef.h
pop3.o: /usr/include/sys/types.h /usr/include/bits/types.h
pop3.o: /usr/include/time.h /usr/include/endian.h /usr/include/bits/endian.h
pop3.o: /usr/include/sys/select.h /usr/include/bits/select.h
pop3.o: /usr/include/bits/sigset.h /usr/include/sys/sysmacros.h
pop3.o: /usr/include/alloca.h /usr/include/string.h /usr/include/syslog.h
pop3.o: /usr/include/sys/syslog.h
pop3.o: /usr/lib/gcc-lib/i386-redhat-linux/egcs-2.91.66/include/stdarg.h
pop3.o: /usr/include/unistd.h /usr/include/bits/posix_opt.h
pop3.o: /usr/include/bits/confname.h /usr/include/getopt.h
pop3.o: /usr/include/arpa/inet.h /usr/include/netinet/in.h
pop3.o: /usr/include/limits.h /usr/include/bits/posix1_lim.h
pop3.o: /usr/include/bits/local_lim.h /usr/include/linux/limits.h
pop3.o: /usr/include/bits/posix2_lim.h /usr/include/stdint.h
pop3.o: /usr/include/bits/wordsize.h /usr/include/bits/socket.h
pop3.o: /usr/include/bits/sockaddr.h /usr/include/asm/socket.h
pop3.o: /usr/include/asm/sockios.h /usr/include/bits/in.h
pop3.o: /usr/include/bits/byteswap.h /usr/include/sys/socket.h authswitch.h
pop3.o: connection.h /usr/include/pwd.h mailspool.h /usr/include/sys/stat.h
pop3.o: /usr/include/bits/stat.h vector.h tokenise.h util.h
stringmap.o: /usr/include/stdlib.h /usr/include/features.h
stringmap.o: /usr/include/sys/cdefs.h /usr/include/gnu/stubs.h
stringmap.o: /usr/lib/gcc-lib/i386-redhat-linux/egcs-2.91.66/include/stddef.h
stringmap.o: /usr/include/sys/types.h /usr/include/bits/types.h
stringmap.o: /usr/include/time.h /usr/include/endian.h
stringmap.o: /usr/include/bits/endian.h /usr/include/sys/select.h
stringmap.o: /usr/include/bits/select.h /usr/include/bits/sigset.h
stringmap.o: /usr/include/sys/sysmacros.h /usr/include/alloca.h
stringmap.o: /usr/include/string.h stringmap.h vector.h util.h
tokenise.o: /usr/include/stdlib.h /usr/include/features.h
tokenise.o: /usr/include/sys/cdefs.h /usr/include/gnu/stubs.h
tokenise.o: /usr/lib/gcc-lib/i386-redhat-linux/egcs-2.91.66/include/stddef.h
tokenise.o: /usr/include/sys/types.h /usr/include/bits/types.h
tokenise.o: /usr/include/time.h /usr/include/endian.h
tokenise.o: /usr/include/bits/endian.h /usr/include/sys/select.h
tokenise.o: /usr/include/bits/select.h /usr/include/bits/sigset.h
tokenise.o: /usr/include/sys/sysmacros.h /usr/include/alloca.h
tokenise.o: /usr/include/string.h tokenise.h vector.h util.h
vector.o: /usr/include/stdlib.h /usr/include/features.h
vector.o: /usr/include/sys/cdefs.h /usr/include/gnu/stubs.h
vector.o: /usr/lib/gcc-lib/i386-redhat-linux/egcs-2.91.66/include/stddef.h
vector.o: /usr/include/sys/types.h /usr/include/bits/types.h
vector.o: /usr/include/time.h /usr/include/endian.h
vector.o: /usr/include/bits/endian.h /usr/include/sys/select.h
vector.o: /usr/include/bits/select.h /usr/include/bits/sigset.h
vector.o: /usr/include/sys/sysmacros.h /usr/include/alloca.h
vector.o: /usr/include/string.h vector.h util.h
