#
# Makefile: makefile for tpop3d
#
# Copyright (c) 2000 Chris Lightfoot. All Rights Reserved.
#
# $Id$
#

VERSION = 0.9
IDLE_TIMEOUT = 30   # seconds before we time out clients

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
#CFLAGS += -DAUTH_PAM
CFLAGS += -DAUTH_PASSWD                            # /etc/passwd
#CFLAGS += -DAUTH_PASSWD -DAUTH_PASSWD_SHADOW       # /etc/shadow

# If you use auth_passwd, you will probably need to link against libcrypt.
LDLIBS += -lcrypt

# These are the libraries which are needed to get PAM support working. On
# Linux, you need -ldl for dynamic linking support; on other systems (e.g.
# FreeBSD) this is not the case. If you are not using PAM at all, comment
# this out.
#LDLIBS  += -lpam -ldl

# If you do not want tpop3d to obtain mailspool locks from PINE and other
# programs which used the Washington University C-Client library, comment out
# the following line (not recommended).
CFLAGS += -DCCLIENT_LOCKING

# If you do not want tpop3d to do flock(2) locking on mailspools (for instance
# if your system attempts to emulate it using fcntl(2) locking, which would
# cause tpop3d to deadlock), then comment out the following line. Note that
# flock locking is always done on c-client lock files if CCLIENT_LOCKING is
# set, since PINE uses flock. FreeBSD users need to comment this out.
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
        tpop3d.cat

SRCS =  auth_mysql.c	\
        auth_pam.c	\
        auth_passwd.c   \
        authswitch.c	\
        config.c	\
        connection.c	\
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

auth_passwd.o: /usr/include/sys/types.h /usr/include/features.h
auth_passwd.o: /usr/include/sys/cdefs.h /usr/include/gnu/stubs.h
auth_passwd.o: /usr/include/bits/types.h
auth_passwd.o: /usr/lib/gcc-lib/i386-redhat-linux/egcs-2.91.66/include/stddef.h
auth_passwd.o: /usr/include/time.h /usr/include/endian.h
auth_passwd.o: /usr/include/bits/endian.h /usr/include/sys/select.h
auth_passwd.o: /usr/include/bits/select.h /usr/include/bits/sigset.h
auth_passwd.o: /usr/include/sys/sysmacros.h /usr/include/grp.h
auth_passwd.o: /usr/include/stdio.h /usr/include/pwd.h /usr/include/stdlib.h
auth_passwd.o: /usr/include/alloca.h /usr/include/string.h
auth_passwd.o: /usr/include/syslog.h /usr/include/sys/syslog.h
auth_passwd.o: /usr/lib/gcc-lib/i386-redhat-linux/egcs-2.91.66/include/stdarg.h
auth_passwd.o: auth_passwd.h authswitch.h stringmap.h vector.h util.h
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
authswitch.o: /usr/include/bits/confname.h /usr/include/getopt.h
authswitch.o: auth_passwd.h authswitch.h stringmap.h vector.h util.h
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
list.o: /usr/include/stdlib.h /usr/include/features.h
list.o: /usr/include/sys/cdefs.h /usr/include/gnu/stubs.h
list.o: /usr/lib/gcc-lib/i386-redhat-linux/egcs-2.91.66/include/stddef.h
list.o: /usr/include/sys/types.h /usr/include/bits/types.h
list.o: /usr/include/time.h /usr/include/endian.h /usr/include/bits/endian.h
list.o: /usr/include/sys/select.h /usr/include/bits/select.h
list.o: /usr/include/bits/sigset.h /usr/include/sys/sysmacros.h
list.o: /usr/include/alloca.h /usr/include/string.h list.h vector.h util.h
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
mailspool.o: /usr/include/alloca.h mailspool.h vector.h tokenise.h md5.h
mailspool.o: global.h util.h
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
main.o: /usr/include/bits/sigstack.h /usr/include/stdio.h
main.o: /usr/include/string.h /usr/include/syslog.h /usr/include/sys/syslog.h
main.o: /usr/lib/gcc-lib/i386-redhat-linux/egcs-2.91.66/include/stdarg.h
main.o: /usr/include/unistd.h /usr/include/bits/posix_opt.h
main.o: /usr/include/bits/confname.h /usr/include/getopt.h
main.o: /usr/include/netinet/in.h /usr/include/stdint.h
main.o: /usr/include/bits/wordsize.h /usr/include/bits/in.h
main.o: /usr/include/bits/byteswap.h /usr/include/arpa/inet.h
main.o: /usr/include/sys/time.h /usr/include/bits/time.h
main.o: /usr/include/sys/wait.h /usr/include/bits/waitflags.h
main.o: /usr/include/bits/waitstatus.h config.h stringmap.h vector.h
main.o: connection.h /usr/include/pwd.h authswitch.h /usr/include/stdlib.h
main.o: /usr/include/alloca.h mailspool.h /usr/include/sys/stat.h
main.o: /usr/include/bits/stat.h tokenise.h list.h util.h
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
pop3.o: /usr/include/bits/confname.h /usr/include/getopt.h authswitch.h
pop3.o: connection.h /usr/include/pwd.h /usr/include/netinet/in.h
pop3.o: /usr/include/limits.h /usr/include/bits/posix1_lim.h
pop3.o: /usr/include/bits/local_lim.h /usr/include/linux/limits.h
pop3.o: /usr/include/bits/posix2_lim.h /usr/include/stdint.h
pop3.o: /usr/include/bits/wordsize.h /usr/include/bits/socket.h
pop3.o: /usr/include/bits/sockaddr.h /usr/include/asm/socket.h
pop3.o: /usr/include/asm/sockios.h /usr/include/bits/in.h
pop3.o: /usr/include/bits/byteswap.h /usr/include/sys/socket.h mailspool.h
pop3.o: /usr/include/sys/stat.h /usr/include/bits/stat.h vector.h tokenise.h
pop3.o: util.h
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
