/*
 * auth_other.c:
 * authenticate using an external program
 *
 * We send a number of variables in the form
 *
 *  key\0value\0
 *
 * terminated by a \0. Variables sent:
 *
 *  key         value
 *  method      PASS or APOP
 *  timestamp   server's RFC1939 timestamp
 *  user        client's username sent with USER or APOP command
 *  pass        client's password from PASS command
 *  digest      client's digest sent with APOP command, in hex
 *  clienthost  client's IP address/hostname
 *  serverhost  server's IP address/hostname
 *
 * The program should respond with a similarly formatted string containing the
 * following variables:
 *
 *  key         value
 *  result      YES or NO
 *  uid         username/uid with which to access mailspool
 *  gid         groupname/gid with which to access mailspool
 *  domain      (optional) domain in which the user has been authenticated
 *  mailbox     (optional) location of mailbox
 *  mboxtype    (optional) name of mailbox driver
 *  logmsg      (optional) message to log
 *
 * The called program will be sent SIGTERM when the authentication driver
 * closes, or in the event that there is a protocol failure. At present,
 * responses need to be timely, since authentication drivers are called
 * synchronously. This may be improved in a later version.
 *
 * The total length of the data sent or received will not exceed 4096 bytes.
 *
 * Copyright (c) 2001 Chris Lightfoot. All rights reserved.
 *
 */

#ifdef HAVE_CONFIG_H
#include "configuration.h"
#endif /* HAVE_CONFIG_H */

#ifdef AUTH_OTHER
static const char rcsid[] = "$Id$";

#include <sys/types.h>

#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <sys/time.h>

#include "authswitch.h"
#include "auth_other.h"
#include "config.h"
#include "math.h"
#include "stringmap.h"
#include "util.h"

#define MAX_DATA_SIZE   4096

char *auth_program;
time_t auth_other_childstart_time;
uid_t auth_other_childuid;
gid_t auth_other_childgid;
volatile pid_t auth_other_child_pid, auth_other_childdied;
volatile int auth_other_childstatus;
struct timeval auth_other_childtimeout;

/* File descriptors used to talk to child. */
volatile int auth_other_childwr = -1, auth_other_childrd = -1;

/* dump:
 * Debugging method. */
void dump(unsigned char *b, size_t len) {
    unsigned char *p;
    char *q;
    char *str = xmalloc(len * 4 + 1);
    for (p = b, q = str; p < b + len; ++p)
        if (*p >= 32 && *p <= 127) *q++ = *p;
        else {
            sprintf(q, "\\x%02x", (unsigned int)*p);
            q += 4;
        }
    *q = 0;
    log_print(LOG_INFO, "dump %s", str);
    xfree(str);
}

static void tvsub(struct timeval *t1, const struct timeval *t2);
static void tvadd(struct timeval *t1, const struct timeval *t2);
static int tvcmp(const struct timeval *t1, const struct timeval *t2);

/* tvadd:
 * t1 += t2 on timevals. */
static void tvadd(struct timeval *t1, const struct timeval *t2) {
    t1->tv_sec  += t2->tv_sec;
    t1->tv_usec += t2->tv_usec;
    while (t1->tv_usec > 1000000) {
        t1->tv_usec -= 1000000;
        t1->tv_sec++;
    }
}

/* tvsub:
 * t1 -= t2 on timevals. */
static void tvsub(struct timeval *t1, const struct timeval *t2) {
    t1->tv_sec  -= t2->tv_sec;
    t1->tv_usec -= t2->tv_usec;
    while (t1->tv_usec < 0) {
        t1->tv_usec += 1000000;
        t1->tv_sec--;
    }
}

/* tvcmp:
 * Is t1 before (-1), after (1), or the same as (0) t2? */
static int tvcmp(const struct timeval *t1, const struct timeval *t2) {
    if (t1->tv_sec < t2->tv_sec) return -1;
    else if (t1->tv_sec > t2->tv_sec) return 1;
    else {
        if (t1->tv_usec < t2->tv_usec) return -1;
        else if (t1->tv_usec > t2->tv_usec) return 1;
        else return 0;
    }
}

/* auth_other_start_child:
 * Start the authentication program, setting up pipes on which to talk to it.
 * Returns 1 on success or 0 on failure. */
int auth_other_start_child() {
    int p1[2], p2[2];
    char *argv[2] = {0};
    char *envp[3] = {"PATH=/bin",  /* XXX path? */
                     "TPOP3D_CONTEXT=auth_other", NULL};

    argv[0] = auth_program;

    /* Generate pipes to talk to the child. */
    if (pipe(p1) == -1 || pipe(p2) == -1) {
        log_print(LOG_ERR, "auth_other_start_child: pipe: %m");
        return 0;
    }

    /* p1[0] becomes the child's standard input.
     * p2[1] becomes the child's standard output.
     * We want p1[1] to be non-blocking. */
    if (fcntl(p1[1], F_SETFL, O_NONBLOCK) == -1) {
        log_print(LOG_ERR, "auth_other_start_child: fcntl: %m");
        close(p1[0]); close(p1[1]); close(p2[0]); close(p2[1]);
        return 0;
    }
   
    switch (auth_other_child_pid = fork()) {
        case 0:
            if (setgid(auth_other_childgid) == -1) {
                log_print(LOG_ERR, "auth_other_start_child: setgid(%d): %m", (int)auth_other_childgid);
                _exit(1);
            } else if (setuid(auth_other_childuid) == -1) {
                log_print(LOG_ERR, "auth_other_start_child: setuid(%d): %m", (int)auth_other_childuid);
                _exit(1);
            }
            
            /* Child. */
            close(0); close(1); close(2);

            /* Set up standard input and output. */
            dup2(p1[0], 0); dup2(p2[1], 1); 
            close(p1[1]); close(p2[0]); 
            
            execve(auth_program, argv, envp);

            /* Failed. */
            _exit(1);

            break;
            
        case -1:
            /* Error. */
            log_print(LOG_ERR, "auth_other_start_child: fork: %m");

            close(p1[0]); close(p1[1]); close(p2[0]); close(p2[1]);
            return 0;

        default:
            /* Parent. */
            auth_other_childwr = p1[1];
            auth_other_childrd = p2[0];
 
            close(p1[0]);
            close(p2[1]);

            log_print(LOG_INFO, "auth_other_start_child: started authentication child `%s'", auth_program);

            return 1;
    }

    return 0; /* NOTREACHED */
}

/* auth_other_kill_child:
 * Kill the authentication child, with SIGTERM at first and then with added
 * SIGKILL-shaped violence if that fails. */
void auth_other_kill_child() {
    struct timeval deadline, now;
    if (auth_other_child_pid == 0) return; /* Already dead. */
    kill(auth_other_child_pid, SIGTERM);
    
    /* Wait for it to expire. */
    gettimeofday(&now, NULL);
    deadline = now;
    tvadd(&deadline, &auth_other_childtimeout);
    
    while (auth_other_child_pid && tvcmp(&now, &deadline) < 0) {
        struct timespec delay = {0, 100000000}; /* 0.1s; note nano not microseconds */
        nanosleep(&delay, NULL);
        gettimeofday(&now, NULL);
    }

    if (auth_other_child_pid) {
        log_print(LOG_WARNING, _("auth_other_kill_child: child failed to die; killing with SIGKILL"));
        kill(auth_other_child_pid, SIGKILL);
        /* Assume this works; it ought to! */
    }
}

/* auth_other_init:
 * Initialise the authentication driver for external programs. This starts the
 * program specified by the auth-other-program config directive, running under
 * the user and group ids in auth-other-user and auth-other-group. */
extern stringmap config;    /* in main.c */
int auth_other_init() {
    char *s;
    float f;

    if (!(s = config_get_string("auth-other-program"))) {
        log_print(LOG_ERR, _("auth_other_init: no program specified"));
        return 0;
    } else {
        struct stat st;
        auth_program = s;
        if (*auth_program != '/') {
            log_print(LOG_ERR, _("auth_other_init: auth-program %s must be an absolute path"), auth_program);
            return 0;
        } else if (stat(auth_program, &st) == -1) {
            log_print(LOG_ERR, _("auth_other_init: auth-program %s: %m"), auth_program);
            return 0;
        }
        /* XXX should fail if it turns out that the program is not executable
         * by the given group and user; but this is a pain to work out. */
    }

    /* Find out the timeout for talking to the program. */
    switch (config_get_float("auth-other-timeout", &f)) {
        case -1:
            log_print(LOG_ERR, _("auth_other_init: value given for auth-other-timeout does not make sense"));
            return 0;

        case 1:
            if (f < 0.0 || f > 10.0) {
                log_print(LOG_ERR, _("auth_other_init: value %f for auth-other-timeout is out of range"), f);
                return 0;
            }
            break;

        default:
            f = 0.75;
    }

    auth_other_childtimeout.tv_sec  = (long)floor(f);
    auth_other_childtimeout.tv_usec = (long)((f - floor(f)) * 1e6);

    /* Find out user and group under which program will run. */
    if (!(s = config_get_string("auth-other-user"))) {
        log_print(LOG_ERR, _("auth_other_init: no user specified"));
        return 0;
    } else if (!parse_uid(s, &auth_other_childuid)) {
        log_print(LOG_ERR, _("auth_other_init: auth-other-user directive `%s' does not make sense"), s);
        return 0;
    }

    if (!(s = config_get_string("auth-other-group"))) {
        log_print(LOG_ERR, _("auth_other_init: no group specified"));
        return 0;
    } else if (!parse_gid(s, &auth_other_childgid)) {
        log_print(LOG_ERR, _("auth_other_init: auth-other-group directive `%s' does not make sense"), s);
        return 0;
    }

    log_print(LOG_INFO, "auth_other_init: %s: will run as uid %d, gid %d", auth_program, (int)auth_other_childuid, (int)auth_other_childgid);

    if (!auth_other_start_child()) {
        log_print(LOG_ERR, _("auth_other_init: failed to start authentication child for first time"));
        return 0;
    }

    return 1;
}

/* auth_other_postfork:
 * Post-fork cleanup: close our copies of the file descriptors. */
void auth_other_postfork() {
    close(auth_other_childwr);
    close(auth_other_childrd);
}

/* auth_other_close:
 * Shut down the authentication driver, killing the external program. */
void auth_other_close() {
    auth_other_kill_child();
}

/* auth_other_send_request:
 * Send the auth child a request consisting of several key/value pairs, as
 * above. Returns 1 on success or 0 on failure. */
int auth_other_send_request(const int nvars, ...) {
    va_list ap;
    int i, ret = 0;
    char buffer[MAX_DATA_SIZE] = {0};
    char *p;
    size_t nn;
    
    if (!auth_other_child_pid) return 0;

    va_start(ap, nvars);

    for (i = 0, p = buffer, nn = 0; i < nvars; ++i) {
        const char *key, *val;
        key = va_arg(ap, const char *);
        nn += strlen(key) + 1;
        if (nn > sizeof(buffer)) goto fail;
        memcpy(p, key, strlen(key) + 1);
        p += strlen(key) + 1;

        val = va_arg(ap, const char *);
        nn += strlen(val) + 1;
        if (nn > sizeof(buffer)) goto fail;
        memcpy(p, val, strlen(val) + 1);
        p += strlen(val) + 1;
    }

    ++nn; /* Terminating \0 */
    if (nn > sizeof(buffer)) {
        log_print(LOG_ERR, _("auth_other_send_request: total size of request would exceed %d bytes"), sizeof(buffer));
        goto fail;
    }

    /* Since write operations are atomic, this will either succeed entirely or
     * fail. In the latter case, it may be with EAGAIN because the child
     * process is blocking; we interpret this as a protocol error. */
    if (try_write(auth_other_childwr, buffer, nn)) ret = 1;
    else {
        if (errno == EAGAIN)
            log_print(LOG_ERR, _("auth_other_send_request: write: write on pipe blocked; killing child"));
        else
            log_print(LOG_ERR, _("auth_other_send_request: write: %m; killing child"));
        auth_other_kill_child();
    }
    
fail:
    va_end(ap);

    return ret;
}

/* auth_other_recv_response:
 * Receive a response from the auth child, as above. Returns a stringmap of
 * responses on success, or NULL on failure. */
stringmap auth_other_recv_response() {
    stringmap S = NULL;
    char buffer[MAX_DATA_SIZE], ends[2] = {0, 0};
    char *p, *q, *r, *s;
    struct timeval deadline;

    if (!auth_other_child_pid) return NULL;

    gettimeofday(&deadline, 0);
    tvadd(&deadline, &auth_other_childtimeout);

    p = buffer;
    do {
        struct timeval timeout = deadline, tt;
        ssize_t rr;
        fd_set readfds;

        FD_ZERO(&readfds);
        FD_SET(auth_other_childrd, &readfds);
        gettimeofday(&tt, NULL);
        if (tvcmp(&deadline, &tt) == -1) {
            log_print(LOG_ERR, _("auth_other_recv_response: timed out waiting for a response; killing child"));
            goto fail;
        }
        tvsub(&timeout, &tt);

        switch (select(auth_other_childrd + 1, &readfds, NULL, NULL, &timeout)) {
            case 1:
                rr = read(auth_other_childrd, p, (buffer + sizeof(buffer) - p));

                switch (rr) {
                    case 0:
                        log_print(LOG_ERR, _("auth_other_recv_response: read: child closed pipe; killing child"));
                        goto fail;

                    case -1:
                        if (errno != EINTR) {
                            log_print(LOG_ERR, _("auth_other_recv_response: read: %m; killing child"));
                            goto fail;
                        } else break;

                    default:
                        p += rr;
                        if (p == buffer + sizeof(buffer)) {
                            log_print(LOG_ERR, _("auth_other_recv_response: total size of response exceeds %d bytes; killing child"), sizeof(buffer));
                            goto fail;
                        }
                }
                break;

            case -1:
                if (errno != EINTR) {
                    log_print(LOG_ERR, _("auth_other_recv_repsonse: select: %m; killing child"));
                    goto fail;
                }

            default:
                break;
        }
    } while (p < buffer + 2 || memcmp(p - 2, ends, 2) != 0); /* Now see whether we have some valid data. */

    /* Try to interpret the passed data. We want to find pairs of
     * \0-terminated strings and put them into the stringmap. */
    S = stringmap_new();
    
    /* q points to the beginning of a key, r to the end of the key, and s to
     * the end of the value, so that [q...r] is the key and [r + 1...s] is the
     * value. */
    q = buffer;
    while (*q && S) {
        r = memchr(q, 0, p - q);
        if (!r || r > (p - 3)) goto formaterror;
        
        s = memchr(r + 1, 0, p - (r + 1));
        if (!s) goto formaterror;

        stringmap_insert(S, q, item_ptr(xstrdup(r + 1)));

        q = s + 1;
        continue;

formaterror:
        log_print(LOG_ERR, _("auth_other_recv_response: response data not correctly formatted; killing child"));
        stringmap_delete_free(S);
        S = NULL;
    }

fail:
    if (!S) auth_other_kill_child();
    return S;
}

/* auth_other_new_apop:
 * Attempt to authenticate a user using APOP, via the child program. */
authcontext auth_other_new_apop(const char *name, const char *local_part, const char *domain, const char *timestamp, const unsigned char *digest, const char *clienthost, const char *serverhost) {
#define MISSING(k)     do { log_print(LOG_ERR, _("auth_other_new_apop: missing key `%s' in response"), (k)); goto fail; } while(0)
#define INVALID(k, v)  do { log_print(LOG_ERR, _("auth_other_new_apop: invalid value `%s' for key `%s' in response"), (v), (k)); goto fail; } while(0)
    char digeststr[33];
    char *p;
    const unsigned char *q;
    stringmap S;
    item *I;
    authcontext a = NULL;
 
    if (!auth_other_child_pid) auth_other_start_child();
    
    for (p = digeststr, q = digest; q < digest + 16; p += 2, ++q)
        sprintf(p, "%02x", (unsigned int)*q);
    if (local_part && domain) {
        if (!auth_other_send_request(8, "method", "APOP", "user", name, "local_part", local_part, "domain", domain, "timestamp", timestamp, "digest", digeststr, "clienthost", clienthost, "serverhost", serverhost))
            return NULL;
    } else if (!auth_other_send_request(6, "method", "APOP", "user", name, "timestamp", timestamp, "digest", digeststr, "clienthost", clienthost, "serverhost", serverhost))
        return NULL;

    if (!(S = auth_other_recv_response()))
        return NULL;

    I = stringmap_find(S, "logmsg");
    if (I) log_print(LOG_INFO, "auth_other_new_apop: child: %s", (char*)I->v);

    I = stringmap_find(S, "result");
    if (!I) MISSING("result");
    
    if (strcmp((char*)I->v, "YES") == 0) {
        uid_t uid;
        gid_t gid;
        struct passwd *pw;
        char *mailbox = NULL, *mboxdrv = NULL, *domain = NULL;

        I = stringmap_find(S, "uid");
        if (!I) MISSING("uid");
        else if (!parse_uid(I->v, &uid)) INVALID("uid", (char*)I->v);
 
        pw = getpwuid(uid);
        if (!pw) INVALID("uid", (char*)I->v);
       
        I = stringmap_find(S, "gid");
        if (!I) MISSING("gid");
        else if (!parse_gid(I->v, &gid)) INVALID("gid", (char*)I->v);

        I = stringmap_find(S, "mailbox");
        if (I) mailbox = (char*)I->v;

        I = stringmap_find(S, "mboxtype");
        if (I) mboxdrv = (char*)I->v;

        I = stringmap_find(S, "domain");
        if (I) domain = (char*)I->v;

        a = authcontext_new(uid, gid, mboxdrv, mailbox, pw->pw_dir);
    } else if (strcmp((char*)I->v, "NO") != 0) INVALID("result", (char*)I->v);
        
fail:
    stringmap_delete_free(S);
    return a;
#undef MISSING
#undef INVALID
}

/* auth_other_new_user_pass:
 * Attempt to authenticate a user using USER/PASS, via the child program. */
authcontext auth_other_new_user_pass(const char *user, const char *local_part, const char *domain, const char *pass, const char *clienthost, const char *serverhost) {
#define MISSING(k)     do { log_print(LOG_ERR, _("auth_other_new_user_pass: missing key `%s' in response"), (k)); goto fail; } while(0)
#define INVALID(k, v)  do { log_print(LOG_ERR, _("auth_other_new_user_pass: invalid value `%s' for key `%s' in response"), (v), (k)); goto fail; } while(0)
    stringmap S;
    item *I;
    authcontext a = NULL;

    if (!auth_other_child_pid) auth_other_start_child();

    if (local_part && domain) {
        if (!auth_other_send_request(7, "method", "PASS", "user", user, "local_part", local_part, "domain", domain, "pass", pass, "clienthost", clienthost, "serverhost", serverhost))
            return NULL;
    } else if (!auth_other_send_request(5, "method", "PASS", "user", user, "pass", pass, "clienthost", clienthost, "serverhost", serverhost))
        return NULL;

    if (!(S = auth_other_recv_response()))
        return NULL;
    
    I = stringmap_find(S, "logmsg");
    if (I) log_print(LOG_INFO, "auth_other_new_user_pass: child: %s", (char*)I->v);

    I = stringmap_find(S, "result");
    if (!I) MISSING("result");
    
    if (strcmp((char*)I->v, "YES") == 0) {
        uid_t uid;
        gid_t gid;
        struct passwd *pw;
        char *mailbox = NULL, *mboxdrv = NULL, *domain = NULL;

        I = stringmap_find(S, "uid");
        if (!I) MISSING("uid");
        else if (!parse_uid(I->v, &uid)) INVALID("uid", (char*)I->v);
 
        pw = getpwuid(uid);
        if (!pw) INVALID("uid", (char*)I->v);
       
        I = stringmap_find(S, "gid");
        if (!I) MISSING("gid");
        else if (!parse_gid(I->v, &gid)) INVALID("gid", (char*)I->v);

        I = stringmap_find(S, "mailbox");
        if (I) mailbox = (char*)I->v;

        I = stringmap_find(S, "mboxtype");
        if (I) mboxdrv = (char*)I->v;

        I = stringmap_find(S, "domain");
        if (I) domain = (char*)I->v;

        a = authcontext_new(uid, gid, mboxdrv, mailbox, pw->pw_dir);
    } else if (strcmp((char*)I->v, "NO") != 0) INVALID("result", (char*)I->v);
        
fail:
    stringmap_delete_free(S);
    return a;
#undef MISSING
#undef INVALID
}

/* auth_other_onlogin:
 * Pass details of a successful login to the authentication program. */
void auth_other_onlogin(const authcontext A, const char *clienthost, const char *serverhost) {
    stringmap S;
    item *I;

    if (!auth_other_child_pid) auth_other_start_child();

    if (!auth_other_send_request(6, "method", "ONLOGIN", "user", A->user, "local_part", A->local_part, "domain", A->domain, "clienthost", clienthost, "serverhost", serverhost)
        || !(S = auth_other_recv_response()))
        return;
    
    I = stringmap_find(S, "logmsg");
    if (I) log_print(LOG_INFO, "auth_other_new_user_pass: child: %s", (char*)I->v);
        
    stringmap_delete_free(S);
}


#endif /* AUTH_OTHER */
