bin_PROGRAMS = tpop3d

tpop3d_SOURCES = auth_mysql.c \
                 auth_pam.c \
                 auth_passwd.c \
                 authswitch.c \
                 cfgdirectives.c \
                 config.c \
                 connection.c \
                 errprintf.c \
                 list.c	\
                 listener.c \
                 locks.c \
                 mailspool.c \
                 main.c \
                 md5c.c \
                 pop3.c	\
                 signals.c \
                 stringmap.c \
                 tokenise.c \
                 util.c \
                 vector.c

tpop3d_LDFLAGS = -L@mysql_root@/lib/mysql

tpop3d_MANS = tpop3d.8

## These need to be distributed along with configure:

AUX_DIST = $(ac_aux_dir)/config.guess \
           $(ac_aux_dir)/config.sub \
           $(ac_aux_dir)/install-sh \
           $(ac_aux_dir)/ltconfig \
           $(ac_aux_dir)/ltmain.sh \
           $(ac_aux_dir)/missing \
           $(ac_aux_dir)/mkinstalldirs

EXTRA_DIST = bootstrap \
             $(ac_aux_dir)/flock-uses-fcntl.c \
             $(ac_aux_dir)/test-file-to-lock

MAINTERCLEANFILES = Makefile.in aclocal.m4 configure configuration.h.in \
                    stamp-h.in $(AUX_DIST)

dist-hook:
	(cd $(distdir) && mkdir $(ac_aux_dir))
	for file in $(AUX_DIST) $(AUX_DIST_EXTRA); do cp $$file $(distdir)/$$file; done
