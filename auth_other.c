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
time_t authchild_start_time;
uid_t authchild_uid;
gid_t authchild_gid;
volatile pid_t authchild_pid, authchild_died;
volatile int authchild_status;
struct timeval authchild_timeout;

/* File descriptors used to talk to child. */
volatile int authchild_wr = -1, authchild_rd = -1;

/* dump:
 * Debugging method.
 */
void dump(unsigned char *b, size_t len) {
    unsigned char *p;
    char *q;
    char *str = malloc(len * 4 + 1);
    for (p = b, q = str; p < b + len; ++p)
        if (*p >= 32 && *p <= 127) *q++ = *p;
        else {
            sprintf(q, "\\x%02x", (unsigned int)*p);
            q += 4;
        }
    *q = 0;
    print_log(LOG_INFO, "dump %s", str);
    free(str);
}

/* tvadd:
 * t1 += t2 on timevals.
 */
void tvadd(struct timeval *t1, const struct timeval *t2) {
    t1->tv_sec  += t2->tv_sec;
    t1->tv_usec += t2->tv_usec;
    while (t1->tv_usec > 1000000) {
        t1->tv_usec -= 1000000;
        t1->tv_sec++;
    }
}

/* tvsub:
 * t1 -= t2 on timevals.
 */
void tvsub(struct timeval *t1, const struct timeval *t2) {
    t1->tv_sec  -= t2->tv_sec;
    t1->tv_usec -= t2->tv_usec;
    while (t1->tv_usec < 0) {
        t1->tv_usec += 1000000;
        t1->tv_sec--;
    }
}

/* tvcmp:
 * Is t1 before (-1), after (1), or the same as (0) t2?
 */
int tvcmp(const struct timeval *t1, const struct timeval *t2) {
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
 * Returns 1 on success or 0 on failure.
 */
int auth_other_start_child() {
    int p1[2], p2[2];
    char *argv[2] = {auth_program, NULL};
    char *envp[3] = {"PATH=/bin",  /* XXX path? */
                     "TPOP3D_CONTEXT=auth_other", NULL};

    /* Generate pipes to talk to the child. */
    if (pipe(p1) == -1 || pipe(p2) == -1) {
        print_log(LOG_ERR, "auth_other_start_child: pipe: %m");
        return 0;
    }

    /* p1[0] becomes the child's standard input.
     * p2[1] becomes the child's standard output.
     * We want p1[1] to be non-blocking.
     */
    if (fcntl(p1[1], F_SETFL, O_NONBLOCK) == -1) {
        print_log(LOG_ERR, "auth_other_start_child: fcntl: %m");
        close(p1[0]); close(p1[1]); close(p2[0]); close(p2[1]);
        return 0;
    }
   
    switch (authchild_pid = fork()) {
        case 0:
            if (setgid(authchild_gid) == -1) {
                print_log(LOG_ERR, "auth_other_start_child: setgid(%d): %m", (int)authchild_gid);
                _exit(1);
            } else if (setuid(authchild_uid) == -1) {
                print_log(LOG_ERR, "auth_other_start_child: setuid(%d): %m", (int)authchild_uid);
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
            print_log(LOG_ERR, "auth_other_start_child: fork: %m");

            close(p1[0]); close(p1[1]); close(p2[0]); close(p2[1]);
            return 0;

        default:
            /* Parent. */
            authchild_wr = p1[1];
            authchild_rd = p2[0];
 
            close(p1[0]);
            close(p2[1]);

            print_log(LOG_INFO, "auth_other_start_child: started authentication child `%s'", auth_program);

            return 1;
    }
}

/* auth_other_kill_child:
 * Kill the authentication child, with SIGTERM at first and then with added
 * SIGKILL-shaped violence if that fails.
 */
void auth_other_kill_child() {
    struct timeval deadline, now;
    if (authchild_pid == 0) return; /* Already dead. */
    kill(authchild_pid, SIGTERM);
    
    /* Wait for it to expire. */
    gettimeofday(&now, NULL);
    deadline = now;
    tvadd(&deadline, &authchild_timeout);
    
    while (authchild_pid && tvcmp(&now, &deadline) < 0) {
        struct timespec delay = {0, 100000000}; /* 0.1s; note nano not microseconds */
        nanosleep(&delay, NULL);
        gettimeofday(&now, NULL);
    }

    if (authchild_pid) {
        print_log(LOG_WARNING, _("auth_other_kill_child: child failed to die; killing with SIGKILL"));
        kill(authchild_pid, SIGKILL);
        /* Assume this works; it ought to! */
    }
}

/* auth_other_init:
 * Initialise the authentication driver for external programs. This starts the
 * program specified by the auth-other-program config directive, running under
 * the user and group ids in auth-other-user and auth-other-group.
 */
extern stringmap config;    /* in main.c */
int auth_other_init() {
    item *I;
    float f;

    if (!(I = stringmap_find(config, "auth-other-program"))) {
        print_log(LOG_ERR, _("auth_other_init: no program specified"));
        return 0;
    } else {
        struct stat st;
        auth_program = (char*)I->v;
        if (*auth_program != '/') {
            print_log(LOG_ERR, _("auth_other_init: auth-program %s should be an absolute path"), auth_program);
            return 0;
        } else if (stat(auth_program, &st) == -1) {
            print_log(LOG_ERR, _("auth_other_init: auth-program %s: %m"), auth_program);
            return 0;
        }
        /* XXX should fail if it turns out that the program is not executable
         * by the given group and user; but this is a pain to work out.
         */
    }

    /* Find out the timeout for talking to the program. */
    switch (config_get_float("auth-other-timeout", &f)) {
        case -1:
            print_log(LOG_ERR, _("auth_other_init: value given for auth-other-timeout does not make sense"));
            return 0;

        case 1:
            if (f < 0.0 || f > 10.0) {
                print_log(LOG_ERR, _("auth_other_init: value %f for auth-other-timeout is out of range"), f);
                return 0;
            }
            break;

        default:
            f = 0.75;
    }

    authchild_timeout.tv_sec  = (long)floor(f);
    authchild_timeout.tv_usec = (long)((f - floor(f)) * 1e6);

    /* Find out user and group under which program will run. */
    if (!(I = stringmap_find(config, "auth-other-user"))) {
        print_log(LOG_ERR, _("auth_other_init: no user specified"));
        return 0;
    } else if (!parse_uid(I->v, &authchild_uid)) {
        print_log(LOG_ERR, _("auth_other_init: auth-other-user directive `%s' does not make sense"), I->v);
        return 0;
    }

    if (!(I = stringmap_find(config, "auth-other-group"))) {
        print_log(LOG_ERR, _("auth_other_init: no group specified"));
        return 0;
    } else if (!parse_gid(I->v, &authchild_gid)) {
        print_log(LOG_ERR, _("auth_other_init: auth-other-group directive `%s' does not make sense"), I->v);
        return 0;
    }

    print_log(LOG_INFO, "auth_other_init: %s: will run as uid %d, gid %d", auth_program, (int)authchild_uid, (int)authchild_gid);

    if (!auth_other_start_child()) {
        print_log(LOG_ERR, _("auth_other_init: failed to start authentication child for first time"));
        return 0;
    }

    return 1;
}

/* auth_other_close:
 * Shut down the authentication driver, killing the external program.
 */
void auth_other_close() {
    auth_other_kill_child();
}

/* auth_other_send_request:
 * Send the auth child a request consisting of several key/value pairs, as
 * above. Returns 1 on success or 0 on failure.
 */
int auth_other_send_request(const int nvars, ...) {
    va_list ap;
    int i, ret = 0;
    char buffer[MAX_DATA_SIZE] = {0};
    char *p;
    size_t nn;
    
    if (!authchild_pid) return 0;

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
        print_log(LOG_ERR, _("auth_other_send_request: total size of request would exceed %d bytes"), sizeof(buffer));
        goto fail;
    }

    /* Since write operations are atomic, this will either succeed entirely or
     * fail. In the latter case, it may be with EAGAIN because the child
     * process is blocking; we interpret this as a protocol error.
     */
    if (try_write(authchild_wr, buffer, nn)) ret = 1;
    else {
        if (errno == EAGAIN)
            print_log(LOG_ERR, _("auth_other_send_request: write: write on pipe blocked; killing child"));
        else
            print_log(LOG_ERR, _("auth_other_send_request: write: %m; killing child"));
        auth_other_kill_child();
    }
    
fail:
    va_end(ap);

    return ret;
}

/* auth_other_recv_response:
 * Receive a response from the auth child, as above. Returns a stringmap of
 * responses on success, or NULL on failure.
 */
stringmap auth_other_recv_response() {
    stringmap S = NULL;
    char buffer[MAX_DATA_SIZE], ends[2] = {0, 0};
    char *p, *q, *r, *s;
    struct timeval deadline;

    if (!authchild_pid) return NULL;

    gettimeofday(&deadline, 0);
    tvadd(&deadline, &authchild_timeout);

    p = buffer;
    do {
        struct timeval timeout = deadline, tt;
        ssize_t rr;
        fd_set readfds;

        FD_ZERO(&readfds);
        FD_SET(authchild_rd, &readfds);
        gettimeofday(&tt, NULL);
        if (tvcmp(&deadline, &tt) == -1) {
            print_log(LOG_ERR, _("auth_other_recv_response: timed out waiting for a response; killing child"));
            goto fail;
        }
        tvsub(&timeout, &tt);

        switch (select(authchild_rd + 1, &readfds, NULL, NULL, &timeout)) {
            case 1:
                rr = read(authchild_rd, p, (buffer + sizeof(buffer) - p));

                switch (rr) {
                    case 0:
                        print_log(LOG_ERR, _("auth_other_recv_response: read: child closed pipe; killing child"));
                        goto fail;

                    case -1:
                        if (errno != EINTR) {
                            print_log(LOG_ERR, _("auth_other_recv_response: read: %m; killing child"));
                            goto fail;
                        } else break;

                    default:
                        p += rr;
                        if (p == buffer + sizeof(buffer)) {
                            print_log(LOG_ERR, _("auth_other_recv_response: total size of response exceeds %d bytes; killing child"), sizeof(buffer));
                            goto fail;
                        }
                }
                break;

            case -1:
                if (errno != EINTR) {
                    print_log(LOG_ERR, _("auth_other_recv_repsonse: select: %m; killing child"));
                    goto fail;
                }

            default:
                break;
        }
    } while (p < buffer + 2 || memcmp(p - 2, ends, 2) != 0); /* Now see whether we have some valid data. */

    /* Try to interpret the passed data. We want to find pairs of
     * \0-terminated strings and put them into the stringmap.
     */
    S = stringmap_new();
    
    /* q points to the beginning of a key, r to the end of the key, and s to
     * the end of the value, so that [q...r] is the key and [r + 1...s] is the
     * value.
     */
    q = buffer;
    while (*q) {
        r = memchr(q, 0, p - q);
        if (!r || r > (p - 3)) goto formaterror;
        
        s = memchr(r + 1, 0, p - (r + 1));
        if (!s) goto formaterror;

        stringmap_insert(S, q, item_ptr(strdup(r + 1)));

        q = s + 1;
        continue;

formaterror:
        print_log(LOG_ERR, _("auth_other_recv_response: response data not correctly formatted; killing child"));
        stringmap_delete_free(S);
        S = NULL;
    }

fail:
    if (!S) auth_other_kill_child();
    return S;
}

/* auth_other_new_apop:
 * Attempt to authenticate a user using APOP, via the child program.
 */
authcontext auth_other_new_apop(const char *name, const char *timestamp, const unsigned char *digest, const char *host) {
#define MISSING(k)     do { print_log(LOG_ERR, _("auth_other_new_apop: missing key `%s' in response"), (k)); goto fail; } while(0)
#define INVALID(k, v)  do { print_log(LOG_ERR, _("auth_other_new_apop: invalid value `%s' for key `%s' in response"), (v), (k)); goto fail; } while(0)
    char digeststr[33];
    char *p;
    const unsigned char *q;
    stringmap S;
    item *I;
    authcontext a = NULL;
 
    if (!authchild_pid) auth_other_start_child();
    
    for (p = digeststr, q = digest; q < digest + 16; p += 2, ++q)
        sprintf(p, "%02x", (unsigned int)*q);
    if (!auth_other_send_request(5, "method", "APOP", "user", name, "timestamp", timestamp, "digest", digeststr, "clienthost", host)
        || !(S = auth_other_recv_response()))
        return NULL;

    I = stringmap_find(S, "logmsg");
    if (I) print_log(LOG_INFO, "auth_other_new_apop: child: %s", (char*)I->v);

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

        a = authcontext_new(uid, gid, mboxdrv, mailbox, pw->pw_dir, domain);
    } else if (strcmp((char*)I->v, "NO") != 0) INVALID("result", (char*)I->v);
        
fail:
    stringmap_delete_free(S);
    return a;
#undef MISSING
#undef INVALID
}

/* auth_other_new_user_pass:
 * Attempt to authenticate a user using USER/PASS, via the child program.
 */
authcontext auth_other_new_user_pass(const char *user, const char *pass, const char *host) {
#define MISSING(k)     do { print_log(LOG_ERR, _("auth_other_new_user_pass: missing key `%s' in response"), (k)); goto fail; } while(0)
#define INVALID(k, v)  do { print_log(LOG_ERR, _("auth_other_new_user_pass: invalid value `%s' for key `%s' in response"), (v), (k)); goto fail; } while(0)
    stringmap S;
    item *I;
    authcontext a = NULL;

    if (!authchild_pid) auth_other_start_child();

    if (!auth_other_send_request(4, "method", "PASS", "user", user, "pass", pass, "clienthost", host)
        || !(S = auth_other_recv_response()))
        return NULL;
    
    I = stringmap_find(S, "logmsg");
    if (I) print_log(LOG_INFO, "auth_other_new_user_pass: child: %s", (char*)I->v);

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

        a = authcontext_new(uid, gid, mboxdrv, mailbox, pw->pw_dir, domain);
    } else if (strcmp((char*)I->v, "NO") != 0) INVALID("result", (char*)I->v);
        
fail:
    stringmap_delete_free(S);
    return a;
#undef MISSING
#undef INVALID
}

#endif /* AUTH_OTHER */
