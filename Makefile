#
# Makefile: makefile for tpop3d
#
# Copyright (c) 2000 Chris Lightfoot. All Rights Reserved.
#
# $Id$
#
# $Log$
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

VERSION = 0.5
IDLE_TIMEOUT = 30   # seconds before we time out clients

MYSQLROOT = /software
# MYSQLROOT = /usr

CFLAGS  += -g -I$(MYSQLROOT)/include/mysql -DTPOP3D_VERSION='"$(VERSION)"' -DIDLE_TIMEOUT=$(IDLE_TIMEOUT) -Wall
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
	makedepend -- --
	rm -f depend
 
# DO NOT DELETE

auth_mysql.o: /usr/include/grp.h /usr/include/features.h
auth_mysql.o: /usr/include/sys/cdefs.h /usr/include/gnu/stubs.h
auth_mysql.o: /usr/include/bits/types.h
auth_mysql.o: /usr/lib/gcc-lib/i386-redhat-linux/egcs-2.91.66/include/stddef.h
auth_mysql.o: /usr/include/stdio.h /usr/include/pwd.h
auth_mysql.o: /software/include/mysql/mysql.h /usr/include/sys/types.h
auth_mysql.o: /usr/include/time.h /usr/include/endian.h
auth_mysql.o: /usr/include/bits/endian.h /usr/include/sys/select.h
auth_mysql.o: /usr/include/bits/select.h /usr/include/bits/sigset.h
auth_mysql.o: /usr/include/sys/sysmacros.h
auth_mysql.o: /software/include/mysql/mysql_com.h
auth_mysql.o: /software/include/mysql/mysql_version.h /usr/include/stdlib.h
auth_mysql.o: /usr/include/alloca.h /usr/include/string.h
auth_mysql.o: /usr/include/syslog.h /usr/include/sys/syslog.h
auth_mysql.o: /usr/lib/gcc-lib/i386-redhat-linux/egcs-2.91.66/include/stdarg.h
auth_mysql.o: auth_mysql.h authswitch.h md5.h global.h /usr/include/limits.h
auth_mysql.o: /usr/include/bits/posix1_lim.h /usr/include/bits/local_lim.h
auth_mysql.o: /usr/include/linux/limits.h /usr/include/bits/posix2_lim.h
auth_mysql.o: stringmap.h vector.h
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
auth_pam.o: stringmap.h vector.h
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
authswitch.o: /usr/include/bits/confname.h /usr/include/getopt.h auth_mysql.h
authswitch.o: authswitch.h auth_pam.h stringmap.h vector.h
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
config.o: config.h stringmap.h vector.h
connection.o: /usr/include/fcntl.h /usr/include/features.h
connection.o: /usr/include/sys/cdefs.h /usr/include/gnu/stubs.h
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
connection.o: vector.h
list.o: /usr/include/stdlib.h /usr/include/features.h
list.o: /usr/include/sys/cdefs.h /usr/include/gnu/stubs.h
list.o: /usr/lib/gcc-lib/i386-redhat-linux/egcs-2.91.66/include/stddef.h
list.o: /usr/include/sys/types.h /usr/include/bits/types.h
list.o: /usr/include/time.h /usr/include/endian.h /usr/include/bits/endian.h
list.o: /usr/include/sys/select.h /usr/include/bits/select.h
list.o: /usr/include/bits/sigset.h /usr/include/sys/sysmacros.h
list.o: /usr/include/alloca.h list.h vector.h
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
mailspool.o: /usr/include/sys/sysmacros.h /usr/include/stdio.h
mailspool.o: /usr/include/string.h /usr/include/syslog.h
mailspool.o: /usr/include/sys/syslog.h
mailspool.o: /usr/lib/gcc-lib/i386-redhat-linux/egcs-2.91.66/include/stdarg.h
mailspool.o: /usr/include/unistd.h /usr/include/bits/posix_opt.h
mailspool.o: /usr/include/bits/confname.h /usr/include/getopt.h
mailspool.o: /usr/include/sys/mman.h /usr/include/bits/mman.h
mailspool.o: /usr/include/sys/stat.h /usr/include/bits/stat.h
mailspool.o: /usr/include/sys/time.h /usr/include/bits/time.h connection.h
mailspool.o: /usr/include/pwd.h /usr/include/netinet/in.h
mailspool.o: /usr/include/stdint.h /usr/include/bits/socket.h
mailspool.o: /usr/include/bits/sockaddr.h /usr/include/asm/socket.h
mailspool.o: /usr/include/asm/sockios.h /usr/include/bits/in.h
mailspool.o: /usr/include/bits/byteswap.h /usr/include/sys/socket.h
mailspool.o: authswitch.h /usr/include/stdlib.h /usr/include/alloca.h
mailspool.o: mailspool.h vector.h md5.h global.h /usr/include/limits.h
mailspool.o: /usr/include/bits/posix1_lim.h /usr/include/bits/local_lim.h
mailspool.o: /usr/include/linux/limits.h /usr/include/bits/posix2_lim.h
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
main.o: /usr/include/sys/stat.h /usr/include/bits/stat.h list.h
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
pop3.o: /usr/include/sys/stat.h /usr/include/bits/stat.h vector.h
stringmap.o: /usr/include/stdlib.h /usr/include/features.h
stringmap.o: /usr/include/sys/cdefs.h /usr/include/gnu/stubs.h
stringmap.o: /usr/lib/gcc-lib/i386-redhat-linux/egcs-2.91.66/include/stddef.h
stringmap.o: /usr/include/sys/types.h /usr/include/bits/types.h
stringmap.o: /usr/include/time.h /usr/include/endian.h
stringmap.o: /usr/include/bits/endian.h /usr/include/sys/select.h
stringmap.o: /usr/include/bits/select.h /usr/include/bits/sigset.h
stringmap.o: /usr/include/sys/sysmacros.h /usr/include/alloca.h
stringmap.o: /usr/include/string.h stringmap.h vector.h
vector.o: /usr/include/stdlib.h /usr/include/features.h
vector.o: /usr/include/sys/cdefs.h /usr/include/gnu/stubs.h
vector.o: /usr/lib/gcc-lib/i386-redhat-linux/egcs-2.91.66/include/stddef.h
vector.o: /usr/include/sys/types.h /usr/include/bits/types.h
vector.o: /usr/include/time.h /usr/include/endian.h
vector.o: /usr/include/bits/endian.h /usr/include/sys/select.h
vector.o: /usr/include/bits/select.h /usr/include/bits/sigset.h
vector.o: /usr/include/sys/sysmacros.h /usr/include/alloca.h
vector.o: /usr/include/string.h vector.h
