/*
 * main.c: main loop for pop3 server
 *
 * Copyright (c) 2000 Chris Lightfoot. All rights reserved.
 *
 * $Log$
 * Revision 1.9  2000/10/18 22:21:23  chris
 * Added timeouts, APOP support.
 *
 * Revision 1.8  2000/10/18 21:34:12  chris
 * Changes due to Mark Longair.
 *
 * Revision 1.7  2000/10/09 23:24:34  chris
 * Minor changess.
 *
 * Revision 1.6  2000/10/09 17:38:21  chris
 * Now handles a proper range of signals.
 *
 * Revision 1.5  2000/10/08 16:53:53  chris
 * Signal handler will always remove lockfile on quit.
 *
 * Revision 1.4  2000/10/07 17:41:16  chris
 * Minor changes.
 *
 * Revision 1.3  2000/10/02 18:21:25  chris
 * SIGCHLD handling etc.
 *
 * Revision 1.2  2000/09/26 22:23:36  chris
 * Various changes.
 *
 * Revision 1.1  2000/09/18 23:43:38  chris
 * Initial revision
 *
 *
 */

static const char rcsid[] = "$Id$";

/* Should be -D... from Makefile. */
#ifndef TPOP3D_VERSION
#   define TPOP3D_VERSION  "(unknown version)"
#endif

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "config.h"
#include "connection.h"
#include "list.h"
#include "stringmap.h"
#include "vector.h"

/* daemon:
 * Become a daemon. From "The Unix Programming FAQ", Andrew Gierth et al.
 */
int daemon(int nochdir, int noclose) {
    switch (fork()) {
        case 0:  break;
        case -1: return -1;
        default: _exit(0);          /* exit the original process */
    }

    if (setsid() < 0)               /* shoudn't fail */
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

/* net_loop:
 * Accept connections and put them into an appropriate state, calling
 * setuid() and fork() when appropriate. listen_addrs is a NULL-terminated
 * list of addresses on which to listen.
 */
int num_running_children = 0;   /* How many children are active. */
int max_running_children = 16;  /* How many children may exist at once. */

connection this_child_connection; /* Stored here so that if a signal terminates the child, the mailspool will still get unlocked. */

void net_loop(struct sockaddr_in **listen_addrs, const size_t num_listen) {
    struct sockaddr_in **sin;
    vector listen_sockets = vector_new();
    list connections = list_new();
    int post_fork = 0;

    /* Set up the listening connections */
    for (sin = listen_addrs; sin < listen_addrs + num_listen; ++sin) {
        int s = socket(PF_INET, SOCK_STREAM, 0);
        if (s == -1)
            syslog(LOG_ERR, "net_loop: socket: %m");
        else {
            int t = 1;
            if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &t, sizeof(t)) == -1) {
                close(s);
                syslog(LOG_ERR, "net_loop: setsockopt: %m");
            } else if (bind(s, *sin, sizeof(struct sockaddr_in)) == -1) {
                close(s);
                syslog(LOG_ERR, "net_loop: bind(%s:%d): %m", inet_ntoa((*sin)->sin_addr), ntohs((*sin)->sin_port));
            } else if (listen(s, SOMAXCONN) == -1) {
                close(s);
                syslog(LOG_ERR, "net_loop: listen: %m");
            } else {
                vector_push_back(listen_sockets, item_long(s));
                syslog(LOG_INFO, "net_loop: listening on %s:%d", inet_ntoa((*sin)->sin_addr), ntohs((*sin)->sin_port));
            }
        }
    }

    if (listen_sockets->n_used == 0) {
        syslog(LOG_ERR, "net_loop: no listening sockets could be opened; aborting");
        exit(1);
    } else syslog(LOG_INFO, "net_loop: tpop3d version " TPOP3D_VERSION " successfully started");

    /* Main select() loop */
    for (;;) {
        fd_set readfds;
        item *t;
        listitem I, J;
        struct timeval tv = {10, 0}; /* Must be less than IDLE_TIMEOUT but otherwise value is unimportant */
        int n = 0;

        FD_ZERO(&readfds);

        if (listen_sockets) vector_iterate(listen_sockets, t) {
            FD_SET(t->l, &readfds);
            if (t->l > n) n = t->l;
        }

        list_iterate(connections, I) {
            int s = ((connection)I->d.v)->s;
            FD_SET(s, &readfds);
            if (s > n) n = s;
        }

        if (select(n + 1, &readfds, NULL, NULL, &tv) >= 0) {
            /* Check for new incoming connections */
            if (listen_sockets) vector_iterate(listen_sockets, t) {
                if (FD_ISSET(t->l, &readfds)) {
                    struct sockaddr_in sin;
                    size_t l = sizeof(sin);
                    int s = accept(t->l, &sin, &l);
                    if (s == -1) syslog(LOG_ERR, "net_loop: accept: %m");
                    else {
                        if (num_running_children >= max_running_children) {
                            char m[] = "-ERR Sorry, I'm too busy right now\r\n";
                            write(s, m, strlen(m));
                            shutdown(s, 2);
                            syslog(LOG_INFO, "net_loop: rejected connection from %s owing to high load", inet_ntoa(sin.sin_addr));
                        } else {
                            connection c = connection_new(s, &sin);
                            if (c) list_push_back(connections, item_ptr(c));
                            syslog(LOG_INFO, "net_loop: connection from %s", inet_ntoa(sin.sin_addr));
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
                        syslog(LOG_INFO, "net_loop: connection_read: peer %s closed connection", inet_ntoa(c->sin.sin_addr));
                        connection_delete(c);
                        I = list_remove(connections, I);
                        if (post_fork) exit(0);
                        if (!I) break;
                    } else if (n < 0) {
                        /* Some sort of error occurred, and we should close
                         * the connection.
                         */
                        syslog(LOG_ERR, "net_loop: connection_read: %m");
                        connection_delete(c);
                        I = list_remove(connections, I);
                        if (post_fork) exit(0);
                        if (!I) break;
                    } else {
                        /* We read some data and should try to interpret
                         * command/s.
                         */
                        pop3command p;
                        while ( (p = connection_parsecommand(c)) ) {
                            switch(connection_do(c, p)) {
                            case close_connection:
                                connection_delete(c);
                                I = list_remove(connections, I);
                                if (post_fork) exit(0);
                                break;
                                
                            case fork_and_setuid:
                                if (num_running_children >= max_running_children) {
                                    connection_sendresponse(c, 0, "Sorry, I'm too busy right now");
                                    syslog(LOG_INFO, "net_loop: rejected login by %s owing to high load", c->a->credential);
                                    connection_delete(c);
                                    I = list_remove(connections, I);
                                    break;
                                } else switch(fork()) {
                                case 0:
                                    /* Child. */
                                    post_fork = 1;

                                    vector_iterate(listen_sockets, t) close(t->l);
                                    vector_delete(listen_sockets);
                                    listen_sockets = NULL;
                                    list_iterate(connections, J) {
                                        if (J != I) J = list_remove(connections, J);
                                        if (!J) break;
                                    }

                                    /* We never access mailspools as root. */
                                    if (!c->a->uid) {
                                        syslog(LOG_ERR, "net_loop: authentication context has UID of 0");
                                        connection_sendresponse(c, 0, "Everything's really bad");
                                        exit(0);
                                    }
                                    
                                    /* Set our gid and uid to that appropriate for the mailspool, as decided by the auth switch. */
                                    if (setgid(c->a->gid) == -1) {
                                        syslog(LOG_ERR, "net_loop: setgid(%d): %m", c->a->gid);
                                        connection_sendresponse(c, 0, "Everything was fine until now, but suddenly I realise I just can't go on. Sorry.");
                                        exit(0);
                                    } else if (setuid(c->a->uid) == -1) {
                                        syslog(LOG_ERR, "net_loop: setuid(%d): %m", c->a->uid);
                                        connection_sendresponse(c, 0, "Everything was fine until now, but suddenly I realise I just can't go on. Sorry.");
                                        exit(0);
                                    }

                                    if (connection_start_transaction(c)) {
                                        connection_sendresponse(c, 1, "Welcome aboard!");
                                        this_child_connection = c;
                                    } else {
                                        connection_sendresponse(c, 0,
                                                errno == EAGAIN ? "Mailspool locked; do you have another concurrent session?"
                                                                : "Oops. Something went wrong.");
                                        exit(0);
                                    }

                                    break;

                                case -1:
                                    /* Error. */
                                    syslog(LOG_ERR, "net_loop: fork: %m");
                                    connection_sendresponse(c, 0, "Everything was fine until now, but suddenly I realise I just can't go on. Sorry.");
                                    connection_delete(c);
                                    I = list_remove(connections, I);
                                    break;
                                    
                                default:
                                    /* Parent. */
                                    close(c->s);
                                    c->s = -1;
                                    connection_delete(c);
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
                } else if (time(NULL) > (((connection)(I->d.v))->lastcmd + IDLE_TIMEOUT)) {
                    /* Connection has timed out. */
                    connection_sendresponse((connection)(I->d.v), 0, "You can hang around all day if you like. I have better things to do.");
                    connection_delete((connection)(I->d.v));
                    I = list_remove(connections, I);
                } else {
                    fprintf(stderr, "connection %p\n", I->d.v);
                }
            }
        }
    }
}

/* die_signal_handler:
 * Signal handler to log a message and quit.
 */
char *this_lockfile;

void die_signal_handler(const int i) {
    if (this_child_connection) connection_delete(this_child_connection);
    if (this_lockfile) unlink(this_lockfile);
    syslog(LOG_ERR, "quit: %s", sys_siglist[i]);
    exit(i + 127);
}

/* child_signal_handler:
 * Signal handler to deal with SIGCHLD.
 */
void child_signal_handler(const int i) {
    int status;
    
    if (waitpid(-1, &status, WNOHANG) != -1)
        --num_running_children;
}

/* set_signals:
 * Set the relevant signals to be ignored/handled.
 */
void set_signals() {
    int ignore_signals[] = {SIGPIPE, SIGINT, SIGHUP, SIGALRM, 0};
    int die_signals[]    = {SIGTERM, SIGQUIT, SIGSEGV, SIGABRT, SIGBUS, SIGFPE, SIGPWR, 0};
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
    fprintf(fp, "\n"
                "tpop3d [options]\n"
                "\n"
                "  -h       display this message\n"
                "  -f file  read configuration from file\n"
                "  -d       do not detach from controlling terminal\n"
                "\n"
                "tpop3d, copyright (c) 2000 Chris Lightfoot <chris@ex-parrot.com>\n"
                "  http://www.ex-parrot.com/~chris/tpop3d/\n"
                "This is tpop3d version " TPOP3D_VERSION "\n"
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
                    break;

                case 'f':
                    ++p;
                    configfile = *p;
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

    /* Identify addresses on which to listen. */
    I = stringmap_find(config, "listen-address");
    listeners = vector_new();
    if (I) {
        vector v = vector_new_from_string(I->v);
        item *J;

        vector_iterate(v, J) {
            struct sockaddr_in *sin;
            char *s = J->v, *r = NULL;

            sin = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));
            
            /* Port */
            r = strchr(s, ':');
            if (r) {
                *r++ = 0;
                sin->sin_port = atoi(r);
                if (!sin->sin_port) {
                    struct servent *se;
                    se = getservbyname(r, "tcp");
                    if (!se) {
                        fprintf(stderr, "%s: specified listen address `%s' has invalid port `%s'\n", configfile, s, r);
                        free(sin);
                        continue;
                    } else sin->sin_port = se->s_port;
                } else sin->sin_port = htons(sin->sin_port);
            } else sin->sin_port = htons(110);
            
            if (!inet_aton(s, &(sin->sin_addr))) {
                struct hostent *he;
                he = gethostbyname(s);
                if (!he) {
                    fprintf(stderr, "%s: gethostbyname: specified listen address `%s' is invalid\n", configfile, s);
                    free(sin);
                    continue;
                } else memcpy(&(sin->sin_addr), he->h_addr, sizeof(struct in_addr));
            }
            vector_push_back(listeners, item_ptr(sin));
        }

        vector_delete_free(v);
    } else {
        struct sockaddr_in *sin;
        sin = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));
        memset(sin, 0, sizeof(struct sockaddr_in));
        sin->sin_port = htons(1201);
        vector_push_back(listeners, item_ptr(sin));
    }

    if (listeners->n_used == 0) {
        fprintf(stderr, "%s: no listen addresses obtained; exiting\n", configfile);
        exit(1);
    }

    /* Find out the maximum number of children we may spawn at once. */
    I = stringmap_find(config, "max-children");
    if (I) {
        max_running_children = atoi((char*)I->v);
        if (!max_running_children) {
            fprintf(stderr, "%s: value of `%s' for max-children does not make sense; exiting\n", configfile, (char *)I->v);
            return 1;
        }
    }

    /* Detach from controlling tty etc. */
    if (!nodaemon) daemon(0, 0);
    
    /* Start logging */
    openlog("tpop3d", (nodaemon ? LOG_PERROR : 0) | LOG_PID | LOG_NDELAY, LOG_MAIL);
    set_signals();

    /* Start the authentication drivers */
    na = authswitch_init();
    if (!na) {
        syslog(LOG_ERR, "no authentication drivers were loaded; aborting.");
        syslog(LOG_ERR, "you may wish to check your config file %s", configfile);
    } else syslog(LOG_INFO, "%d authentication drivers successfully loaded", na);

   
    net_loop((struct sockaddr_in**)listeners->ary, listeners->n_used);

    authswitch_close();
    vector_delete_free(listeners);

    return 0;
}
