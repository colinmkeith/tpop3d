#
# Makefile: makefile for tpop3d
#
# Copyright (c) 2000 Chris Lightfoot. All Rights Reserved.
#
# $Id$
#
# $Log$
# Revision 1.12  2000/10/31 23:17:29  chris
# flock locking now a compile-time option.
#
# Revision 1.11  2000/10/31 20:37:22  chris
# Minor changes.
#
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

VERSION = 0.7
IDLE_TIMEOUT = 30   # seconds before we time out clients

CFLAGS  += -g -DTPOP3D_VERSION='"$(VERSION)"' -DIDLE_TIMEOUT=$(IDLE_TIMEOUT) -Wall
LDFLAGS += -g
LDLIBS  += -ldl -lpam

# If you do not want tpop3d to obtain mailspool locks from PINE and other
# programs which used the Washington University C-Client library, comment out
# the following line (not recommended).
CFLAGS += -DCCLIENT_LOCKING

# If you do not want tpop3d to do flock(2) locking on mailspools (for instance
# if your system attempts to emulate it using fcntl(2) locking, which would
# cause tpop3d to deadlock), then comment out the following line. Note that
# flock locking is always done on c-client lock files if CCLIENT_LOCKING is
# set, since PINE uses flock.
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
	tokenise.c      \
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
	tokenise.h      \
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

auth_pam.o: /usr/include/grp.h /usr/include/features.h
auth_pam.o: /usr/include/sys/cdefs.h /usr/include/gnu/stubs.h
auth_pam.o: /usr/include/bits/types.h
auth_pam.o: /usr/lib/gcc-lib/i386-redhat-linux/egcs-2.91.66/include/stddef.h
auth_pam.o: /usr/include/stdio.h /usr/include/pwd.h /usr/include/stdlib.h
auth_pam.o: /usr/include/sys/types.h /usr/include/time.h
auth_pam.o: /usr/include/endian.h /usr/include/bits/endian.h
auth_pam.o: /usr/include/sys/select.h /usr/include/bits/select.h
auth_pam.o: /usr/include/bits/sigset.h /usr/include/sys/sysmacros.h
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
connection.o: /usr/include/netinet/in.h /usr/include/stdint.h
connection.o: /usr/include/bits/socket.h /usr/include/bits/sockaddr.h
connection.o: /usr/include/asm/socket.h /usr/include/asm/sockios.h
connection.o: /usr/include/bits/in.h /usr/include/bits/byteswap.h
connection.o: /usr/include/sys/socket.h /usr/include/sys/utsname.h
connection.o: /usr/include/bits/utsname.h connection.h authswitch.h
connection.o: mailspool.h /usr/include/sys/stat.h /usr/include/bits/stat.h
connection.o: vector.h util.h
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
mailspool.o: /usr/include/bits/time.h connection.h /usr/include/pwd.h
mailspool.o: /usr/include/netinet/in.h /usr/include/stdint.h
mailspool.o: /usr/include/bits/socket.h /usr/include/bits/sockaddr.h
mailspool.o: /usr/include/asm/socket.h /usr/include/asm/sockios.h
mailspool.o: /usr/include/bits/in.h /usr/include/bits/byteswap.h
mailspool.o: /usr/include/sys/socket.h authswitch.h /usr/include/stdlib.h
mailspool.o: /usr/include/alloca.h mailspool.h vector.h md5.h global.h
mailspool.o: /usr/include/limits.h /usr/include/bits/posix1_lim.h
mailspool.o: /usr/include/bits/local_lim.h /usr/include/linux/limits.h
mailspool.o: /usr/include/bits/posix2_lim.h util.h
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
main.o: /usr/include/bits/sockaddr.h /usr/include/asm/socket.h
main.o: /usr/include/asm/sockios.h /usr/include/signal.h
main.o: /usr/include/bits/signum.h /usr/include/bits/siginfo.h
main.o: /usr/include/bits/sigaction.h /usr/include/bits/sigcontext.h
main.o: /usr/include/asm/sigcontext.h /usr/include/bits/sigstack.h
main.o: /usr/include/stdio.h /usr/include/string.h /usr/include/syslog.h
main.o: /usr/include/sys/syslog.h
main.o: /usr/lib/gcc-lib/i386-redhat-linux/egcs-2.91.66/include/stdarg.h
main.o: /usr/include/unistd.h /usr/include/bits/posix_opt.h
main.o: /usr/include/bits/confname.h /usr/include/getopt.h
main.o: /usr/include/netinet/in.h /usr/include/stdint.h
main.o: /usr/include/bits/in.h /usr/include/bits/byteswap.h
main.o: /usr/include/arpa/inet.h /usr/include/sys/time.h
main.o: /usr/include/bits/time.h /usr/include/sys/wait.h
main.o: /usr/include/bits/waitflags.h /usr/include/bits/waitstatus.h config.h
main.o: stringmap.h vector.h connection.h /usr/include/pwd.h authswitch.h
main.o: /usr/include/stdlib.h /usr/include/alloca.h mailspool.h
main.o: /usr/include/sys/stat.h /usr/include/bits/stat.h list.h util.h
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
pop3.o: /usr/include/stdint.h /usr/include/bits/socket.h
pop3.o: /usr/include/bits/sockaddr.h /usr/include/asm/socket.h
pop3.o: /usr/include/asm/sockios.h /usr/include/bits/in.h
pop3.o: /usr/include/bits/byteswap.h /usr/include/sys/socket.h mailspool.h
pop3.o: /usr/include/sys/stat.h /usr/include/bits/stat.h vector.h util.h
stringmap.o: /usr/include/stdlib.h /usr/include/features.h
stringmap.o: /usr/include/sys/cdefs.h /usr/include/gnu/stubs.h
stringmap.o: /usr/lib/gcc-lib/i386-redhat-linux/egcs-2.91.66/include/stddef.h
stringmap.o: /usr/include/sys/types.h /usr/include/bits/types.h
stringmap.o: /usr/include/time.h /usr/include/endian.h
stringmap.o: /usr/include/bits/endian.h /usr/include/sys/select.h
stringmap.o: /usr/include/bits/select.h /usr/include/bits/sigset.h
stringmap.o: /usr/include/sys/sysmacros.h /usr/include/alloca.h
stringmap.o: /usr/include/string.h stringmap.h vector.h util.h
vector.o: /usr/include/stdlib.h /usr/include/features.h
vector.o: /usr/include/sys/cdefs.h /usr/include/gnu/stubs.h
vector.o: /usr/lib/gcc-lib/i386-redhat-linux/egcs-2.91.66/include/stddef.h
vector.o: /usr/include/sys/types.h /usr/include/bits/types.h
vector.o: /usr/include/time.h /usr/include/endian.h
vector.o: /usr/include/bits/endian.h /usr/include/sys/select.h
vector.o: /usr/include/bits/select.h /usr/include/bits/sigset.h
vector.o: /usr/include/sys/sysmacros.h /usr/include/alloca.h
vector.o: /usr/include/string.h vector.h util.h
