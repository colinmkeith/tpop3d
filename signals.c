/*
 * signals.c:
 * Signal handlers for tpop3d.
 *
 * Copyright (c) 2001 Chris Lightfoot. All rights reserved.
 *
 */

static const char rcsid[] = "$Id$";

#ifdef HAVE_CONFIG_H
#include "configuration.h"
#endif /* HAVE_CONFIG_H */

#include <errno.h>
#include <signal.h>
#include <syslog.h>

#include <sys/wait.h>

#include "connection.h"
#include "pidfile.h"
#include "signals.h"
#include "util.h"

#ifdef APPALLING_BACKTRACE_HACK
#include <execinfo.h>

/* appalling_backtrace_hack:
 * Attempt to read a backtrace of the current stack; can be called from a
 * signal handler if the program dies unexpectedly. */
#define BT_LEVELS   16
void appalling_backtrace_hack() {
    void *func_addr[BT_LEVELS];
    int i, n;

    n = backtrace(func_addr, BT_LEVELS);

    log_print(LOG_ERR, _("appalling_backtrace_hack: stack trace of program begins"));
    
    for (i = 0; i < n; ++i)
        log_print(LOG_ERR, "appalling_backtrace_hack:    [%d]: %p", i, func_addr[i]);

    log_print(LOG_ERR, _("appalling_backtrace_hack: stack trace of program ends"));
    log_print(LOG_ERR, _("appalling_backtrace_hack: use addr2line(1) to resolve the addresses"));
}
#endif /* APPALLING_BACKTRACE_HACK */

/* set_signals:
 * Set the relevant signals to be ignored/handled. */
void set_signals() {
    int ignore_signals[]    = {SIGPIPE, SIGHUP, SIGALRM, SIGUSR1, SIGUSR2, SIGFPE,
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
    int terminate_signals[] = {SIGINT, SIGTERM, 0};
    int restart_signals[]   = {SIGHUP, 0};
    int die_signals[]       = {SIGQUIT, SIGABRT, SIGSEGV, SIGBUS, SIGILL, 0};
    int *i;
    struct sigaction sa = {0};

    for (i = ignore_signals; *i; ++i)
        xsignal(*i, SIG_IGN);
    
    for (i = terminate_signals; *i; ++i)
        xsignal(*i, terminate_signal_handler);
    
    for (i = restart_signals; *i; ++i)
        xsignal(*i, restart_signal_handler);

    for (i = die_signals; *i; ++i)
        xsignal(*i, die_signal_handler);

    /* SIGCHLD is special. */
    sa.sa_handler = child_signal_handler;
    sa.sa_flags = SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);
}

extern sig_atomic_t foad, restart;       /* in netloop.c */

/* terminate_signal_handler:
 * Signal handler to handle orderly termination of the program. */
void terminate_signal_handler(const int i) {
    foad = i;
}

/* die_signal_handler:
 * Signal handler to log a message and quit.
 *
 * XXX This is bad, because we call out to functions which may use malloc or
 * file I/O or anything else. However, we quit immediately afterwards, so it's
 * probably OK. Alternatively we would have to siglongjmp out, but that would
 * be undefined behaviour too. */
extern connection this_child_connection;    /* in main.c */

extern char *pidfile;    /* in main.c */
extern int post_fork;    /* in main.c */

void die_signal_handler(const int i) {
    struct sigaction sa = {0};
/*    log_print(LOG_ERR, "quit: %s", sys_siglist[i]); */
    log_print(LOG_ERR, _("quit: signal %d post_fork = %d"), i, post_fork); /* Some systems do not have sys_siglist. */
#ifdef APPALLING_BACKTRACE_HACK
    appalling_backtrace_hack();
#endif /* APPALLING_BACKTRACE_HACK */
    if (this_child_connection) connection_delete(this_child_connection);
    if (!post_fork && pidfile)
        remove_pid_file(pidfile);
    sa.sa_handler = SIG_DFL;
    sigaction(i, &sa, NULL);
    raise(i);
}

/* child_signal_handler:
 * Signal handler to deal with SIGCHLD. */
extern int num_running_children; /* in main.c */

#ifdef AUTH_OTHER
extern pid_t auth_other_child_pid, auth_other_childdied; /* in auth_other.c */
extern int auth_other_childwr, auth_other_childrd, auth_other_childstatus;
#endif /* AUTH_OTHER */

/* Save information about any child which dies with a signal. */
pid_t child_died;
int child_died_signal;

void child_signal_handler(const int i) {
    pid_t pid;
    int e, status;

    /* Save errno. */
    e = errno;

    while (1) {
        pid = waitpid(-1, &status, WNOHANG);
        if (pid > 0) {
#ifdef REALLY_UGLY_PAM_HACK
            extern auth_pam_child_pid; /* in auth_pam.c */
            if (pid == auth_pam_child_pid)
                ; /* Do nothing; in principle we should check to see if it crashed. */
            else
#endif /* REALLY_UGLY_PAM_HACK */
#ifdef AUTH_OTHER
            if (pid == auth_other_child_pid) {
                auth_other_child_pid = 0;
                auth_other_childdied = pid;
                auth_other_childstatus = status;
                close(auth_other_childwr);
                close(auth_other_childrd);
            } else
#endif /* AUTH_OTHER */
            {
                --num_running_children;
                /* If the child process was killed by a signal, save its PID
                 * so that the main daemon can report it. Note that we dont't
                 * cope with the situation of several children dying nearly
                 * simultaneously, but this is a `shouldn't happen'
                 * anyway.... */
                if (WIFSIGNALED(status)) {
                    child_died = pid;
                    child_died_signal = WTERMSIG(status);
                }
            }
        } else if (pid == 0 || (pid == -1 && errno != EINTR)) {
            errno = e;
            return;
        }
    }
}

/* restart_signal_handler:
 * Signal handler to restart the server on receiving a SIGHUP. */
void restart_signal_handler(const int i) {
    if (!post_fork) {
        foad = i;
        restart = 1;
    }
}


