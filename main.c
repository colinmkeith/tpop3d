/*
 * main.c:
 * main loop for pop3 server
 *
 * Copyright (c) 2001 Chris Lightfoot. All rights reserved.
 *
 */

static const char copyright[] = "$Copyright: (c) 2001 Chris Lightfoot. All rights reserved. $";
static const char rcsid[] = "$Id$";

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>

#include "config.h"
#include "connection.h"
#include "errprintf.h"
#include "list.h"
#include "stringmap.h"
#include "vector.h"
#include "util.h"

/* The socket send buffer is set to this, so that we don't end up in a
 * position that we send so much data that the client will not have received
 * all of it before we time them out.
 */
#define MAX_DATA_IN_FLIGHT      8192

/* Should we be verbose about data going to/from the client? */
int verbose;

#ifdef __SVR4
/* inet_aton:
 * Implementation of inet_aton for machines (Solaris [cough]) which do not
 * have it.
 */
int inet_aton(const char *s, struct in_addr *ip);

int inet_aton(const char *s, struct in_addr *ip) {                              
    in_addr_t i = inet_addr(s);                                                 
    if (i == ((in_addr_t)-1)) return 0;                                         
    memcpy(ip, &i, sizeof(int));                                                
    return 1;                                                                   
}                                                                               
#endif

/* xwrite:
 * Write some data, taking account of short writes.
 */
ssize_t xwrite(int fd, const void *buf, size_t count) {
    size_t c = count;
    const char *b = (const char*)buf;
    while (c > 0) {
        int e = write(fd, b, count);
        if (e > 0) {
            c -= e;
            b += e;
        } else return e;
    } while (c > 0);
    return count;
}

/* daemon:
 * Become a daemon. From "The Unix Programming FAQ", Andrew Gierth et al.
 */
int daemon(int nochdir, int noclose) {
    switch (fork()) {
        case 0:  break;
        case -1: return -1;
        default: _exit(0);          /* exit the original process */
    }

    if (setsid() < 0)               /* shouldn't fail */
        return -1;

    switch (fork()) {
        case 0:  break;
        case -1: return -1;
        default: _exit(0);
    }

    if (!nochdir) chdir("/");

    if (!noclose) {
        int i, j = sysconf(_SC_OPEN_MAX); /* getdtablesize()? */
        for (i = 0; i < j; ++i) close(i);
        open("/dev/null",O_RDWR);
        dup(0); dup(0);
    }

    return 0;
}

/* print_log:
 * Because many systems do not have LOG_PERROR, we use a custom function to
 * write an error to the system log, and optionally to standard error as
 * well.
 */
int log_stderr;

void print_log(int priority, const char *fmt, ...) {
    char *s;
    va_list ap;
    va_start(ap, fmt);
    s = verrprintf(fmt, ap);
    va_end(ap);
    syslog(priority, "%s", s);
    if (log_stderr) fprintf(stderr, "%s\n", s);
    free(s);
}

/* For virtual-domains support, we need to find the address and domain name
 * associated with a socket on which we are listening.
 */
typedef struct _listener {
    struct sockaddr_in sin;
    char *domain;
    int s;
} *listener;

listener listener_new(const struct sockaddr_in *addr, const char *domain);
void listener_delete(listener L);

/* listener_new:
 * Create a new listener object, listening on the specified address.
 */
listener listener_new(const struct sockaddr_in *addr, const char *domain) {
    listener L;
    struct hostent *he;
    
    L = (listener)malloc(sizeof(struct _listener));
    memset(L, 0, sizeof(struct _listener));
    memcpy(&(L->sin), addr, sizeof(struct sockaddr_in));
    L->s = socket(PF_INET, SOCK_STREAM, 0);
    if (L->s == -1) {
        print_log(LOG_ERR, "listener_new: socket: %m");
        goto fail;
    } else {
        int t = 1;
        if (setsockopt(L->s, SOL_SOCKET, SO_REUSEADDR, &t, sizeof(t)) == -1) {
            print_log(LOG_ERR, "listener_new: setsockopt: %m");
            goto fail;
        } else if (fcntl(L->s, F_SETFL, O_NONBLOCK) == -1) {
            print_log(LOG_ERR, "listener_new: fcntl: %m");
            goto fail;
        } else if (bind(L->s, (struct sockaddr*)addr, sizeof(struct sockaddr_in)) == -1) {
            print_log(LOG_ERR, "listener_new: bind(%s:%d): %m", inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
            goto fail;
        } else if (listen(L->s, SOMAXCONN) == -1) {
            print_log(LOG_ERR, "listener_new: listen: %m");
            goto fail;
        }
    }

    /* Now, we need to find the domain associated with this socket. */
    if (!domain) {
        he = gethostbyaddr((char *)&(addr->sin_addr), sizeof(addr->sin_addr), AF_INET);
        if (!he) {
            print_log(LOG_WARNING, "listener_new: gethostbyaddr(%s): cannot resolve name", inet_ntoa(addr->sin_addr));
            print_log(LOG_WARNING, "listener_new: %s: no domain suffix can be appended for this address", inet_ntoa(addr->sin_addr));
        } else {
            /* We need to find out an appropriate domain suffix for the address.
             * FIXME we just take the first address with a "." in it, and use the
             * part after the ".".
             */
            char **a, *b;
            b = strchr(he->h_name, '.');
            if (b && *(b + 1)) {
                L->domain = strdup(b + 1);
            } else 
                for (a = he->h_aliases; *a; ++a) {
                    char *b;
                    fprintf(stderr, "%s\n", *a);
                    if ((b = strchr(*a, '.')) && *(b + 1)) {
                        L->domain = strdup(b + 1);
                        break;
                    }
                }

            if (!L->domain)
                print_log(LOG_WARNING, "listener_new: %s: no suitable domain suffix found for this address", inet_ntoa(addr->sin_addr));
        }
    } else L->domain = strdup(domain);

    /* Last try; use the nodename from uname(2). */
    if (!L->domain) {
        struct utsname u;
        if (uname(&u) == -1) {
            print_log(LOG_WARNING, "listener_new: uname: %m");
            print_log(LOG_WARNING, "listener_new: %s: using domain suffix `x.invalid'", inet_ntoa(addr->sin_addr));
            L->domain = strdup("x.invalid");
        } else {
            print_log(LOG_WARNING, "listener_new: %s: using fallback domain suffix %s", inet_ntoa(addr->sin_addr), u.nodename);
            L->domain = strdup(u.nodename);
        }
    }

    return L;

fail:
    listener_delete(L);
    return NULL;
}

/* listener_delete:
 * Delete a listener object, closing the associated socket.
 */
void listener_delete(listener L) {
    if (!L) return;
    if (L->s != -1) close(L->s); /* Do not shutdown(2). */
    if (L->domain) free(L->domain);
    free(L);
}

/* net_loop:
 * Accept connections and put them into an appropriate state, calling
 * setuid() and fork() when appropriate. listen_addrs is a NULL-terminated
 * list of addresses on which to listen.
 */
int num_running_children = 0;   /* How many children are active. */
int max_running_children = 16;  /* How many children may exist at once. */

long int timeout_seconds = 30;

connection this_child_connection; /* Stored here so that if a signal terminates the child, the mailspool will still get unlocked. */

void net_loop(vector listen_addrs) {
    list connections = list_new();
    int post_fork = 0;

    print_log(LOG_INFO, "net_loop: tpop3d version " TPOP3D_VERSION " successfully started");

    /* Main select() loop */
    for (;;) {
        fd_set readfds;
        item *t;
        listitem I, J;
        struct timeval tv = {1, 0}; /* Must be less than IDLE_TIMEOUT but otherwise value is unimportant */
        int n = 0, e;

        FD_ZERO(&readfds);

        if (!post_fork && listen_addrs) vector_iterate(listen_addrs, t) {
            int s = ((listener)t->v)->s;
            FD_SET(s, &readfds);
            if (s > n) n = s;
        }

        list_iterate(connections, I) {
            int s = ((connection)I->d.v)->s;
            FD_SET(s, &readfds);
            if (s > n) n = s;
        }

        e = select(n + 1, &readfds, NULL, NULL, &tv);
        if (e == -1 && errno != EINTR) {
            print_log(LOG_WARNING, "net_loop: select: %m");
        } else if (e >= 0) {
            /* Check for new incoming connections */
            if (!post_fork && listen_addrs) vector_iterate(listen_addrs, t) {
                listener L = (listener)t->v;
                if (FD_ISSET(L->s, &readfds)) {
                    struct sockaddr_in sin;
                    size_t l = sizeof(sin);
                    int s = accept(L->s, (struct sockaddr*)&sin, &l);
                    int a = MAX_DATA_IN_FLIGHT;

                    if (s == -1) {
                        if (errno != EAGAIN) print_log(LOG_ERR, "net_loop: accept: %m");
                    } else if (setsockopt(s, SOL_SOCKET, SO_SNDBUF, &a, sizeof(a)) == -1) {
                        /* Set a small send buffer so that we get usefully blocking writes. */
                        print_log(LOG_ERR, "net_loop: setsockopt: %m");
                        close(s);
                    } else if (fcntl(s, F_SETFL, 0) == -1) {
                        /* Switch off non-blocking mode, in case it is inherited. */
                        print_log(LOG_ERR, "net_loop: fcntl: %m");
                        close(s);
                    } else {
                        if (num_running_children >= max_running_children) {
                            char m[] = "-ERR Sorry, I'm too busy right now\r\n";
                            xwrite(s, m, strlen(m));
                            shutdown(s, 2);
                            close(s);
                            print_log(LOG_INFO, "net_loop: rejected connection from %s owing to high load", inet_ntoa(sin.sin_addr));
                        } else {
                            connection c = connection_new(s, &sin, L->domain);
                            if (c) list_push_back(connections, item_ptr(c));
                            print_log(LOG_INFO, "net_loop: client %s: connected", c->idstr);
                        }
                    }
                }
            }

            /* Monitor existing connections */
            list_iterate(connections, I) {
                if (FD_ISSET(((connection)I->d.v)->s, &readfds)) {
                    int n;
                    connection c = (connection)I->d.v;
                    n = connection_read(c);
                    if (n == 0) {
                        /* Peer closed the connection */
                        print_log(LOG_INFO, "net_loop: connection_read: client %s: closed connection", c->idstr);
                        connection_delete(c);
                        I = list_remove(connections, I);
                        if (post_fork) exit(0);
                        if (!I) break;
                    } else if (n < 0 && errno != EINTR) {
                        /* Some sort of error occurred, and we should close
                         * the connection.
                         */
                        print_log(LOG_ERR, "net_loop: connection_read: client %s: disconnected: %m", c->idstr);
                        connection_delete(c);
                        I = list_remove(connections, I);
                        if (post_fork) exit(0);
                        if (!I) break;
                    } else {
                        /* We read some data and should try to interpret
                         * command/s.
                         */
                        pop3command p;
                        while (c && (p = connection_parsecommand(c))) {
                            switch(connection_do(c, p)) {
                            case close_connection:
                                connection_delete(c);
                                c = NULL;
                                I = list_remove(connections, I);
                                if (post_fork) exit(0);
                                break;
                                
                            case fork_and_setuid:
                                if (num_running_children >= max_running_children) {
                                    connection_sendresponse(c, 0, "Sorry, I'm too busy right now");
                                    print_log(LOG_INFO, "net_loop: client %s: rejected login owing to high load", c->idstr);
                                    connection_delete(c);
                                    I = list_remove(connections, I);
                                    c = NULL;
                                    break;
                                } else switch(fork()) {
                                case 0:
                                    /* Child. */
                                    post_fork = 1;

                                    vector_iterate(listen_addrs, t) listener_delete((listener)t->v);
                                    vector_delete(listen_addrs);
                                    listen_addrs = NULL;

                                    list_iterate(connections, J) {
                                        if (J != I) {
                                            close(((connection)J->d.v)->s);
                                            ((connection)J->d.v)->s = -1;
                                            J = list_remove(connections, J);
                                        }
                                        if (!J) break;
                                    }

                                    /* We never access mailspools as root. */
                                    if (!c->a->uid) {
                                        print_log(LOG_ERR, "net_loop: client %s: authentication context has UID of 0", c->idstr);
                                        connection_sendresponse(c, 0, "Everything's really bad");
                                        connection_delete(c);
                                        exit(0);
                                    }

                                    /* Set our gid and uid to that appropriate for the mailspool, as decided by the auth switch. */
                                    if (setgid(c->a->gid) == -1) {
                                        print_log(LOG_ERR, "net_loop: setgid(%d): %m", c->a->gid);
                                        connection_sendresponse(c, 0, "Something bad happened, and I just can't go on. Sorry.");
                                        connection_delete(c);
                                        exit(0);
                                    } else if (setuid(c->a->uid) == -1) {
                                        print_log(LOG_ERR, "net_loop: setuid(%d): %m", c->a->uid);
                                        connection_sendresponse(c, 0, "Something bad happened, and I realise I just can't go on. Sorry.");
                                        connection_delete(c);
                                        exit(0);
                                    }

                                    if (connection_start_transaction(c)) {
                                        char s[1024];
                                        snprintf(s, 1024, "Welcome aboard! You have %d messages.", c->m->index->n_used);
                                        connection_sendresponse(c, 1, s);
                                        this_child_connection = c;
                                    } else {
                                        connection_sendresponse(c, 0,
                                                errno == EAGAIN ? "Mailspool locked; do you have another concurrent session?"
                                                                : "Oops. Something went wrong.");
                                        connection_delete(c);
                                        exit(0);
                                    }

                                    I = NULL;

                                    break;

                                case -1:
                                    /* Error. */
                                    print_log(LOG_ERR, "net_loop: fork: %m");
                                    connection_sendresponse(c, 0, "Everything was fine until now, but suddenly I realise I just can't go on. Sorry.");
                                    connection_delete(c);
                                    c = NULL;
                                    I = list_remove(connections, I);
                                    break;
                                    
                                default:
                                    /* Parent. */
                                    close(c->s);
                                    c->s = -1; /* Don't shutdown the socket */
                                    connection_delete(c);
                                    c = NULL;
                                    I = list_remove(connections, I);
                                    ++num_running_children;
                                }

                            default:;
                            }

                            pop3command_delete(p);
                            
                            if (!I) break;
                        }

                        if (!I) break;
                    }
                } else if ( timeout_seconds && (time(NULL) > (((connection)(I->d.v))->idlesince + timeout_seconds)) ) {
                    /* Connection has timed out. */
#ifndef NO_SNIDE_COMMENTS
                    connection_sendresponse((connection)(I->d.v), 0, "You can hang around all day if you like. I have better things to do.");
#else
                    connection_sendresponse((connection)(I->d.v), 0, "Client has been idle for too long.");
#endif
                    print_log(LOG_INFO, "net_loop: timed out client %s", ((connection)I->d.v)->idstr);
                    connection_delete((connection)(I->d.v));
                    if (post_fork) exit(0);
                    I = list_remove(connections, I);
                    if (!I) break;
                }
            }
        }
    }
}

/* die_signal_handler:
 * Signal handler to log a message and quit.
 *
 * XXX This is bad, because we call out to functions which may use malloc or
 * file I/O or anything else. However, we quit immediately afterwards, so it's
 * probably OK. Alternatively we would have to siglongjmp out, but that would
 * be undefined behaviour too.
 */
void die_signal_handler(const int i) {
    struct sigaction sa;
/*    print_log(LOG_ERR, "quit: %s", sys_siglist[i]); */
    print_log(LOG_ERR, "quit: signal %d", i); /* Some systems do not have sys_siglist. */
    if (this_child_connection) connection_delete(this_child_connection);
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_DFL;
    sigaction(i, &sa, NULL);
    raise(i);
}

/* child_signal_handler:
 * Signal handler to deal with SIGCHLD.
 */
void child_signal_handler(const int i) {
    int status;
    
    while (waitpid(-1, &status, WNOHANG) > 0)
        --num_running_children;
}

/* set_signals:
 * Set the relevant signals to be ignored/handled.
 */
void set_signals() {
    int ignore_signals[] = {SIGPIPE, SIGHUP, SIGALRM, SIGUSR1, SIGUSR2, SIGFPE,
#ifdef SIGIO        
        SIGIO,
#endif
#ifdef SIGVTALRM
        SIGVTALRM,
#endif
#ifdef SIGLOST
        SIGLOST,
#endif
#ifdef SIGPWR
        SIGPWR,
#endif
        0};
    int die_signals[] = {SIGINT, SIGTERM, SIGQUIT, SIGABRT, SIGSEGV, SIGBUS, 0};
    int *i;
    struct sigaction sa;

    for (i = ignore_signals; *i; ++i) {
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = SIG_IGN;
        sigaction(*i, &sa, NULL);
    }

    for (i = die_signals; *i; ++i) {
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = die_signal_handler;
        sigaction(*i, &sa, NULL);
    }

    /* SIGCHLD is special. */
    sa.sa_handler = child_signal_handler;
    sa.sa_flags = SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);
}

/* usage:
 * Print usage information.
 */
void usage(FILE *fp) {
    fprintf(fp, "tpop3d, version " TPOP3D_VERSION "\n"
                "\n"
                "tpop3d [options]\n"
                "\n"
                "  -h       display this message\n"
                "  -f file  read configuration from file\n"
                "  -d       do not detach from controlling terminal\n"
                "  -v       log traffic to/from server for debugging purposes\n"
                "\n"
                "tpop3d, copyright (c) 2000-2001 Chris Lightfoot <chris@ex-parrot.com>\n"
                "home page: http://www.ex-parrot.com/~chris/tpop3d/\n"
                "\n"
                "This program is free software; you can redistribute it and/or modify\n"
                "it under the terms of the GNU General Public License as published by\n"
                "the Free Software Foundation; either version 2 of the License, or\n"
                "(at your option) any later version.\n"
                "\n");
}

/* main:
 * Read config file, set up authentication and proceed to main loop.
 */
stringmap config;
extern int append_domain; /* Do we automatically try user@domain if user alone fails to authenticate? In pop3.c. */

int main(int argc, char **argv) {
    vector listeners;
    item *I;
    char **p;
    int nodaemon = 0;
    char *configfile = "/etc/tpop3d.conf";
    int na;

    /* Read the options. */
    for (p = argv + 1; *p; ++p) {
        if (**p == '-') {
            switch (*(*p + 1)) {
                case 'h':
                    usage(stdout);
                    return 0;

                case 'd':
                    nodaemon = 1;
                    log_stderr = 1;
                    break;

                case 'f':
                    ++p;
                    configfile = *p;
                    break;

                case 'v':
                    verbose = 1;
                    break;

                default:
                    fprintf(stderr, "Unrecognised option -%c\n", *(*p + 1));
                    usage(stderr);
                    return 1;
            }
        } else {
            usage(stderr);
            return 1;
        }
    }

    /* Read the config file. */
    config = read_config_file(configfile);
    if (!config) return 1;

    /* Detach from controlling tty etc. */
    if (!nodaemon) daemon(0, 0);

    /* Start logging */
    openlog("tpop3d", LOG_PID | LOG_NDELAY, LOG_MAIL);

    /* Identify addresses on which to listen.
     * The syntax for these is <addr>[:port][(domain)].
     */
    I = stringmap_find(config, "listen-address");
    listeners = vector_new();
    if (I) {
        tokens t = tokens_new(I->v, " \t");
        item *J;

        vector_iterate(t->toks, J) {
            struct sockaddr_in sin = {0};
            listener L;
            char *s = J->v, *r = NULL, *domain = NULL;

            sin.sin_family = AF_INET;

            /* Specified domain. */
            r = strchr(s, '(');
            if (r) {
                if (*(s + strlen(s) - 1) != ')') {
                    print_log(LOG_ERR, "%s: syntax for listen address `%s' is incorrect\n", configfile, s);
                    continue;
                }

                *r++ = 0;
                *(r + strlen(r) - 1) = 0;
                domain = r;
            }
            
            /* Port. */
            r = strchr(s, ':');
            if (r) {
                *r++ = 0;
                sin.sin_port = atoi(r);
                if (!sin.sin_port) {
                    struct servent *se;
                    se = getservbyname(r, "tcp");
                    if (!se) {
                        print_log(LOG_ERR, "%s: specified listen address `%s' has invalid port `%s'\n", configfile, s, r);
                        continue;
                    } else sin.sin_port = se->s_port;
                } else sin.sin_port = htons(sin.sin_port);
            } else sin.sin_port = htons(110); /* pop-3 */
            
            /* Address. */
            if (!inet_aton(s, &(sin.sin_addr))) {
                struct hostent *he;
                he = gethostbyname(s);
                if (!he) {
                    print_log(LOG_ERR, "%s: gethostbyname: specified listen address `%s' is invalid\n", configfile, s);
                    continue;
                } else memcpy(&(sin.sin_addr), he->h_addr, sizeof(struct in_addr));
            }

            L = listener_new(&sin, domain);
            if (L) {
                vector_push_back(listeners, item_ptr(L));
                print_log(LOG_INFO, "listening on address %s, port %d%s%s", inet_ntoa(L->sin.sin_addr), htons(L->sin.sin_port), (L->domain ? " with domain " : ""), (L->domain ? L->domain : ""));
            }
        }

        tokens_delete(t);
    }

    if (listeners->n_used == 0) {
        print_log(LOG_ERR, "%s: no listen addresses obtained; exiting\n", configfile);
        return 1;
    }

    /* Find out the maximum number of children we may spawn at once. */
    I = stringmap_find(config, "max-children");
    if (I) {
        max_running_children = atoi((char*)I->v);
        if (!max_running_children) {
            print_log(LOG_ERR, "%s: value of `%s' for max-children does not make sense; exiting\n", configfile, (char *)I->v);
            return 1;
        }
    }

    /* Should we automatically append domain names and retry authentication? */
    I = stringmap_find(config, "append-domain");
    if (I && (!strcmp(I->v, "yes") || !strcmp(I->v, "true"))) append_domain = 1;

    /* Find out how long we wait before timing out... */
    I = stringmap_find(config, "timeout-seconds");
    if (I) {
        char * endptr;
        errno = 0;
        timeout_seconds = strtol(I->v, &endptr, 10);
        if(endptr == I->v) {
            print_log(LOG_ERR, "%s: value of `%s' for timeout-seconds does not make sense; exiting\n", configfile, (char *)I->v); 
            return 1;
        }
        if(timeout_seconds < 0) {
            print_log(LOG_ERR, "%s: cannot specify a negative value (`%s') for timeout-seconds; exiting\n", configfile, (char *)I->v); 
            return 1;
        }
        if(errno == ERANGE) {
            print_log(LOG_ERR, "%s: value of `%s' is too large; exiting\n", configfile, (char *)I->v); 
            return 1;
        }
    } else {
        timeout_seconds = 30;
    }
   
    set_signals();

    /* Start the authentication drivers */
    na = authswitch_init();
    if (!na) {
        print_log(LOG_ERR, "no authentication drivers were loaded; aborting.");
        print_log(LOG_ERR, "you may wish to check your config file %s", configfile);
        return 1;
    } else print_log(LOG_INFO, "%d authentication drivers successfully loaded", na);
   
    net_loop(listeners);

    authswitch_close();
    vector_delete_free(listeners);

    return 0;
}

#undef malloc
#undef free

#if 0
char *mystrdup(char *f, int l, char *s) {
    char *p = malloc(strlen(s) + 1);
    strcpy(p, s);
    fprintf(stderr, "[%d] %s:%d: %p = strdup(\"%s\")\n", getpid(), f, l, p, s);
    return p;
}

void *mymalloc(char *f, int l, size_t n) {
    void *p = malloc(n);
    if (!p) return NULL;
    fprintf(stderr, "[%d] %s:%d: %p = malloc(%d)\n", getpid(), f, l, p, n);
    return p;
}

void myfree(char *f, int l, void *p) {
    free(p);
    fprintf(stderr, "[%d] %s:%d: free(%p)\n", getpid(), f, l, p);
}
#endif 
