/*
 * main.c:
 * Entry point, initialisation code and main loop for pop3 server.
 *
 * Copyright (c) 2001 Chris Lightfoot. All rights reserved.
 *
 */

static const char copyright[] = "$Copyright: (c) 2001 Chris Lightfoot. All rights reserved. $";
static const char rcsid[] = "$Id$";

#ifdef HAVE_CONFIG_H
#include "configuration.h"
#endif /* HAVE_CONFIG_H */

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#ifdef USE_TCP_WRAPPERS
#include <tcpd.h>
int allow_severity = LOG_INFO;
int deny_severity  = LOG_NOTICE;
#endif

#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/utsname.h>

#include "authswitch.h"
#include "config.h"
#include "listener.h"
#include "pidfile.h"
#include "signals.h"
#include "stringmap.h"
#include "tokenise.h"
#include "vector.h"
#include "util.h"

/* Data structure representing the config file, and global variable which we
 * set from it. */
stringmap config;

/* Various configuration options. */
extern int append_domain;           /* Do we automatically try user@domain if user alone fails to authenticate? In pop3.c. */
extern int strip_domain;            /* Do we automatically try user if user@domain fails to authenticate? */
extern int apop_only;               /* Quit after receiving USER. */
int log_stderr;                     /* Are log messages also sent to standard error? */
int verbose;                        /* Should we be verbose about data going to/from the client? */


char *pidfile = NULL;               /* The name of a PID file to use; if NULL, don't use one. */
char *tcpwrappersname;              /* The daemon name to give to TCP Wrappers. */

/* Various things in netloop.c */
extern vector listeners;
extern int max_running_children, post_fork, timeout_seconds;
extern sig_atomic_t foad, restart;

void net_loop(void);


#define EXIT_REMOVING_PIDFILE(n) do { if (pidfile) remove_pid_file(pidfile); exit((n)); } while (0)

/* usage STREAM
 * Print usage information to STREAM.  */
void usage(FILE *fp) {
    fprintf(fp, _(
"tpop3d, version %s\n"
"\n"
"Synopsis: tpop3d -h | [-f file] [-p file] [-d] [-v]\n"
"\n"
"  -h               Display this message\n"
"  -f file          Read configuration from file\n"
"                   (default: %s/tpop3d.conf)\n"
"  -p file          Write PID to file (default: don't use a PID file)\n"
"  -d               Do not detach from controlling terminal\n"
"  -v               Log traffic to/from server for debugging purposes\n"
            )
#ifdef USE_TLS
            _(
"  -P               Permit reading of certificate/private key pass phrases\n"
"                   for TLS operation from the terminal on startup\n"
            )
#endif
"\n"
                , TPOP3D_VERSION, CONFIG_DIR);

    /* Describe the compiled-in options. */
    authswitch_describe(fp);
    mailbox_describe(fp);

#ifdef USE_TCP_WRAPPERS
    fprintf(fp, _("This tpop3d has TCP Wrappers support.\n\n"));
#else
    fprintf(fp, _("This tpop3d does not have TCP Wrappers support.\n\n"));
#endif
    
    fprintf(fp, _(
"tpop3d, copyright (c) 2000-2 Chris Lightfoot <chris@ex-parrot.com>;\n"
"portions copyright (c) 2001-2 Mark Longair, Paul Makepeace, Sebastien Thomas.\n"
"home page: http://www.ex-parrot.com/~chris/tpop3d/\n"
"\n"
"This program is free software; you can redistribute it and/or modify\n"
"it under the terms of the GNU General Public License as published by\n"
"the Free Software Foundation; either version 2 of the License, or\n"
"(at your option) any later version.\n"
"\n"
                ));
}

/* parse_listeners STMT
 * Parse STMT as a list of specifications for addresses on which to listen,
 * creating listener objects as we go. Returns the number of listeners
 * successfully created.
 *
 * The syntax for a listener spec is
 *
 *  addr[:port][(domain)|/regex/][;tls=(immediate|stls),<certificate-file>[,private-key-file]
 *
 */
int parse_listeners(const char *stmt) {
    tokens t;
    char **ll;
    int N = 0;
    
    t = tokens_new(stmt, " \t");

    for (ll = t->toks; ll < t->toks + t->num; ++ll) {
        listener L;
        int i;
        char *s, *p;
        struct sockaddr_in sin = {0};
        char *host = NULL, *port = NULL, *domain = NULL;
#ifdef USE_TLS
        enum tls_mode tls = none;
        char *cert = NULL, *pkey = NULL;
#endif
#ifdef MASS_HOSTING
        char *regex = NULL;
#endif

        s = *ll;
        
        /* Address. */
        i = strcspn(s, ":(/;");
        host = xstrndup(s, i);

        p = s + i;
        
        if (*p == ':') {
            /* Port. */
            ++p;
            i = strcspn(p, "(/;");
            port = xstrndup(p, i);
            p += i;
        }
        
        if (*p == '/') {
            /* Regular expression matching domain. */
#ifdef MASS_HOSTING
            ++p;
            i = strcspn(p, "/");
            if (p[i] != '/') {
                log_print(LOG_ERR, _("parse_listeners: `%s': missing trailing `/'"), s);
                goto skip;
            }
            regex = xstrndup(p, i);
            p += i + 1;
#else
            log_print(LOG_ERR, _("parse_listeners: `%s': this tpop3d does not support mass-hosting regular expressions"), s);
            goto skip;
#endif
        } else if (*p == '(') {
            /* Explicit domain. */
            i = strcspn(p, ")");
            if (p[i] != ')') {
                log_print(LOG_ERR, _("parse_listeners: `%s': missing `)'"), s);
                goto skip;
            }
            domain = xstrndup(p, i);
            p += i + 1;
        }


        if (strncmp(p, ";tls=", 5) == 0) {
#ifdef USE_TLS
            /* TLS mode */
            p += 5;
            if (strncmp(p, "immediate", 9) == 0)
                tls = immediate;
            else if (strncmp(p, "stls", 4) == 0)
                tls = stls;
            else {
                log_print(LOG_ERR, _("parse_listeners: `%s': unknown TLS mode `%.*s'"), s, strcspn(p, ","), p);
                goto skip;
            }

            /* Certificate file */
            if (!(p = strchr(p, ',')) || !*(++p)) {
                log_print(LOG_ERR, _("parse_listeners: `%s': no TLS certificate specified"), s);
                goto skip;
            }

            i = strcspn(p, ",");
            cert = xstrndup(p, i);
            p += i;
            
            /* Optional separate private-key file */
            if (*p) {
                ++p;
                if (!*p) {
                    log_print(LOG_ERR, _("parse_listeners: `%s': TLS private key file is blank"), s);
                    goto skip;
                }
                pkey = xstrdup(p);
            }
#else
            log_print(LOG_ERR, _("parse_listeners: `%s': this tpop3d does not support TLS"), s);
            goto skip;
#endif
        } else if (*p) {
            log_print(LOG_ERR, _("parse_listeners: `%s': trailing garbage"), s);
            goto skip;
        }

        /* Yay! Got everything we need.... */

        /* Turn address and port in to numerical values. */
        if (port) {
            sin.sin_port = atoi(port);
            if (!sin.sin_port) {
                struct servent *se;
                se = getservbyname(port, "tcp");
                if (!se) {
                    log_print(LOG_ERR, _("parse_listeners: `%s': invalid port `%s'"), s, port);
                    continue;
                } else sin.sin_port = se->s_port;
            } else sin.sin_port = htons(sin.sin_port);
        } else sin.sin_port = htons(tls == immediate ? 995 : 110); /* pop-3 */

        /* Address. */
        if (!inet_aton(host, &(sin.sin_addr))) {
            struct hostent *he;
            he = gethostbyname(host);
            if (!he) {
                log_print(LOG_ERR, _("parse_listeners: `%s': invalid listen address `%s'"), s, host);
                continue;
            } else memcpy(&sin.sin_addr, he->h_addr, sizeof sin.sin_addr);
        }

        
        if ((L = listener_new(&sin, domain
#ifdef MASS_HOSTING
                                , regex
#endif
#ifdef USE_TLS
                                , tls, cert, pkey
#endif
                            ))) {
            char msg[1024];     /* XXX */
            vector_push_back(listeners, item_ptr(L));
            ++N;
            /* Log a helpful message. */
            sprintf(msg, _("listening on address %s:%d"), inet_ntoa(L->sin.sin_addr), htons(L->sin.sin_port));
#ifdef MASS_HOSTING
            if (L->have_re)
                sprintf(msg + strlen(msg), ", regex /%s/", L->regex);
#endif
#ifdef USE_TLS
            if (L->tls.mode != none)
                sprintf(msg + strlen(msg), "; TLS mode %s", L->tls.mode == immediate ? "immediate" : "STLS");
#endif
            log_print(LOG_INFO, _("parse_listeners: %s"), msg);
        }
        
skip:
        xfree(host);
        xfree(port);
#ifdef USE_TLS
        xfree(cert);
        xfree(pkey);
#endif
#ifdef MASS_HOSTING
        xfree(regex);
#endif
    }

    tokens_delete(t);

    return N;
}

/* main:
 * Read config file, set up authentication and proceed to main loop. */
char optstring[] = "+hdvf:p:"
#ifdef USE_TLS
                    "P"
#endif
                    ;

#if defined(MBOX_BSD) && defined(MBOX_BSD_SAVE_INDICES)
extern int mailspool_save_indices;  /* in mailspool.c */
#endif

int main(int argc, char **argv, char **envp) {
    int nodaemon = 0;
    char *configfile = CONFIG_DIR"/tpop3d.conf", *s;
    int na, c;
#ifdef USE_TLS
    extern int noreadpassphrase; /* in tls.c */
#endif

#ifdef MTRACE_DEBUGGING
    mtrace(); /* Memory debugging on glibc systems. */
#endif /* MTRACE_DEBUGGING */
    
    /* Read the options. */
    opterr = 0;
    while ((c = getopt(argc, argv, optstring)) != EOF) {
        switch(c) {
            case 'h':
                usage(stdout);
                return 0;

            case 'd':
                nodaemon = 1;
                log_stderr = 1;
                break;

            case 'v':
                verbose = 1;
                break;

            case 'f':
                configfile = optarg;
                break;

            case 'p':
                pidfile = optarg;
                break;

#ifdef USE_TLS
            case 'P':
                noreadpassphrase = 0;
                break;
#endif

            case '?':
            default:
                if (strchr(optstring, optopt))
                    fprintf(stderr, _("tpop3d: option -%c requires an argument\n"), optopt);
                else
                    fprintf(stderr, _("tpop3d: unrecognised option -%c\n"), optopt);
                usage(stderr);
                return 1;
        }
    }

    /* Read the config file. */
    config = read_config_file(configfile);
    if (!config) return 1;

    /* The config file may specify that we aren't to run in daemon mode. */
    if (config_get_bool("no-detach"))
        nodaemon = 1;

    /* ... or that we are to log to standard error. */
    if (config_get_bool("log-stderr")) {
        if (nodaemon)
            log_stderr = 1;
        else
            fprintf(stderr, _("tpop3d: will not log to standard error when running detached"));
    }

    /* Detach from controlling tty etc. */
    if (!nodaemon) daemon(0, 0);

    /* Start logging. */
    log_init();

    /* Perhaps we have been asked to save metadata caches for BSD mailspools? */
#if defined(MBOX_BSD) && defined(MBOX_BSD_SAVE_INDICES)
    if (config_get_string("mailspool-index")) {
        mailspool_save_indices = 1;
        log_print(LOG_INFO, _("experimental BSD mailbox metadata cache enabled"));
    }
#endif

    /* We may have been compiled with TCP wrappers support. */
#ifdef USE_TCP_WRAPPERS
    if (!(tcpwrappersname = config_get_string("tcp-wrappers-name")))
        tcpwrappersname = "tpop3d";
    log_print(LOG_INFO, _("TCP Wrappers support enabled, using daemon name `%s'"), tcpwrappersname);
#endif
    
    /* Try to write PID file. */
    if (pidfile) {
retry_pid_file:
        switch (write_pid_file(pidfile)) {
            case pid_file_success:
                break;

            case pid_file_existence: {
                pid_t pid;
                switch (read_pid_file(pidfile, &pid)) {
                    case pid_file_success:
                        if (kill(pid, 0)) {
                            log_print(LOG_ERR, _("%s: stale PID file; removing it"), pidfile);
                            if (unlink(pidfile) == -1) {
                                log_print(LOG_ERR, _("%s: stale PID file: unlink: %m"), pidfile);
                                return 1;
                            } else goto retry_pid_file; /* harmful? */
                            
                        } else {
                            log_print(LOG_ERR, _("%s: tpop3d already running, with process ID %d; exiting"), (int)pid);
                            return 1;
                        }
                        break;
                        
                    default:
                        log_print(LOG_ERR, _("%s: PID file seems to be invalid; exiting."), pidfile);
                        return 1;
                }
                break;
            }

            case pid_file_error:
                log_print(LOG_ERR, _("%s: %m: couldn't write PID file; exiting."), pidfile);
                return 1;
        }
    }

    /* Identify addresses on which to listen.
     * The syntax for these is <addr>[:port][(domain)]. */
    s = config_get_string("listen-address");
    listeners = vector_new();
    if (s) 
        parse_listeners(s);

    if (listeners->n_used == 0) {
        log_print(LOG_ERR, _("%s: no listen addresses obtained; exiting"), configfile);
        EXIT_REMOVING_PIDFILE(1);
    }

    /* Find out the maximum number of children we may spawn at once. */
    switch(config_get_int("max-children", &max_running_children)) {
        case -1:
            log_print(LOG_ERR, _("%s: value given for max-children does not make sense; exiting"), configfile);
            EXIT_REMOVING_PIDFILE(1);

        case 1:
            if (max_running_children < 1) {
                log_print(LOG_ERR, _("%s: value for max-children must be 1 or greater; exiting"), configfile);
                EXIT_REMOVING_PIDFILE(1);
            }
            break;

        default:
            max_running_children = 16;
    }

    /* Should we automatically append or strip domain names and retry authentication? */
    if (config_get_bool("append-domain"))
        append_domain = 1;
    if (config_get_bool("strip-domain"))
        strip_domain = 1;

    if (append_domain && strip_domain)
        log_print(LOG_WARNING, _("%s: specifying append-domain and strip-domain does not make much sense"));

    /* Should we disconnect any client which sends a USER command? */
    if (config_get_bool("apop-only"))
        apop_only = 1;

    /* Find out how long we wait before timing out.... */
    switch (config_get_int("timeout-seconds", &timeout_seconds)) {
        case -1:
            log_print(LOG_ERR, _("%s: value given for timeout-seconds does not make sense; exiting"), configfile);
            EXIT_REMOVING_PIDFILE(1);

        case 1:
            if (timeout_seconds < 1) {
                log_print(LOG_ERR, _("%s: value for timeout-seconds must be 1 or greater; exiting"), configfile);
                EXIT_REMOVING_PIDFILE(1);
            }
            break;

        default:
            timeout_seconds = 30;
    }

    set_signals();

    /* Start the authentication drivers. */
    na = authswitch_init();
    if (!na) {
        log_print(LOG_ERR, _("no authentication drivers were loaded; aborting."));
        log_print(LOG_ERR, _("you may wish to check your config file %s"), configfile);
        EXIT_REMOVING_PIDFILE(1);
    } else log_print(LOG_INFO, _("%d authentication drivers successfully loaded"), na);
   
    net_loop();

    if (!post_fork)
        authswitch_close();

    if (listeners) {
        item *I;
        vector_iterate(listeners, I) listener_delete((listener)I->v);
        vector_delete(listeners);
    }

    stringmap_delete_free(config);
    
    /* We may have got here because we're supposed to terminate and restart. */
    if (restart) {
        execve(argv[0], argv, envp);
        log_print(LOG_ERR, "%s: %m", argv[0]);
    }
    
    EXIT_REMOVING_PIDFILE(0);
}

