/*
 * locks.c:
 * Various means of locking BSD mailspools.
 * 
 * Some or all of fcntl, flock and .lock locking are done, along with a rather
 * comedy attempt at cclient locking, which is only there so that PINE figures
 * out when the user is attempting to pick up her mail using POP3 in the
 * middle of a PINE session. cclient locks aren't made, just stolen from PINE
 * using the wacky `Kiss Of Death' described in the cclient documentation.
 *
 * Note also that we lock the whole mailspool for reading and writing. This is
 * pretty crap, but it makes it easier to make the program fast. In principle,
 * we could just lock the existing section of the file, so that the MTA could
 * deliver new messages on to the end of it, and then stat it when we were
 * about to apply changes in the UPDATE state, to see whether it had grown.
 *
 * Copyright (c) 2001 Chris Lightfoot. All rights reserved.
 *
 */

static const char rcsid[] = "$Id$";

#ifdef HAVE_CONFIG_H
#include "configuration.h"
#endif /* HAVE_CONFIG_H */

#ifdef MBOX_BSD

#include "locks.h"

#include <errno.h>
#include <fcntl.h>
#ifdef WITH_CCLIENT_LOCKING
#   include <signal.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>

#include "util.h"

#ifdef WITH_FCNTL_LOCKING
/* fcntl_lock:
 * Attempt to lock a file using fcntl(2) locking. Returns 0 or success, or -1
 * on error. */
int fcntl_lock(int fd) {
    struct flock fl = {0};

    /* Set up flock structure to lock entire file. */
    fl.l_type   = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start  = 0;
    fl.l_len    = 0;

    return fcntl(fd, F_SETLK, &fl);
}

/* fcntl_unlock:
 * Attempt to unlock a file using fcntl(2) locking. Returns 0 on success, or
 * -1 on error. */
int fcntl_unlock(int fd) {
    struct flock fl = {0};

    /* Set up flock structure to unlock entire file. */
    fl.l_type   = F_UNLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start  = 0;
    fl.l_len    = 0;

    return fcntl(fd, F_SETLK, &fl);
}
#endif /* WITH_FCNTL_LOCKING */

#if defined(WITH_FLOCK_LOCKING) || (defined(WITH_CCLIENT_LOCKING) && !defined(CCLIENT_USES_FCNTL))
/* flock_lock:
 * Attempt to lock a file using flock(2) locking. Returns 0 on success, or -1
 * on failure. */
int flock_lock(int fd) {
    return flock(fd, LOCK_EX | LOCK_NB);
}

/* flock_unlock:
 * Attempt to unlock a file using flock(2) locking. Returns 0 on success or -1
 * on failure. */
int flock_unlock(int fd) {
    return flock(fd, LOCK_UN);
}
#endif /* WITH_FLOCK_LOCKING */

#ifdef WITH_DOTFILE_LOCKING
/* dotfile_check_stale:
 * If the named lockfile exists, then check whether the PID inside it is one
 * for an extant process. If it is not, remove it. */
static void dotfile_check_stale(const char *file) {
    int fd;
    char buf[16] = {0};
    fd = open(file, O_RDONLY);
    if (fd == -1) return;
    if (read(fd, buf, sizeof(buf) - 1) > 0) {
        int i;
        i = strspn(buf, "0123456789");
        if (i > 0 && buf[i] == '\n') {
            pid_t p;
            /* Have a valid PID, possibly. */
            buf[i] = 0;
            p = (pid_t)atoi(buf);
            if (p > 1 && kill(p, 0) == -1 && errno == ESRCH
                && unlink(file) == 0)
                /* File exists but process doesn't. */
                log_print(LOG_INFO, _("dotfile_check_stale: removed stale lockfile `%s' (pid was %d)"), file, (int)p);
        }
    }
    close(fd);
}

/* dotfile_lock:
 * Attempt to lock a file by constructing a lockfile having the name of the
 * file with ".lock" appended. Returns 0 on success or -1 on failure. */
int dotfile_lock(const char *name) {
    char *lockfile = xmalloc(strlen(name) + 6), *hitchfile = NULL;
    char pidstr[16];
    struct utsname uts;
    int fd = -1, rc, r = -1;
    struct stat st;

    sprintf(pidstr, "%d\n", (int)getpid());

    /* Make name for lockfile. */
    if (!lockfile) goto fail;
    sprintf(lockfile, "%s.lock", name);

    dotfile_check_stale(lockfile);

    /* Make a name for a hitching-post file. */
    if (uname(&uts) == -1) goto fail;
    hitchfile = xmalloc(strlen(name) + strlen(uts.nodename) + 24);
    if (!hitchfile) goto fail;
    sprintf(hitchfile, "%s.%ld.%ld.%s", name, (long)getpid(), (long)time(NULL), uts.nodename);

    fd = open(hitchfile, O_EXCL | O_CREAT | O_WRONLY, 0440);
    if (fd == -1) {
        log_print(LOG_ERR, _("dotfile_lock(%s): unable to create hitching post: %m"), name);
        goto fail;
    }

    if (xwrite(fd, pidstr, strlen(pidstr)) != strlen(pidstr)) {
        log_print(LOG_ERR, _("dotfile_lock(%s): unable to write PID to hitching post: %m"), name);
        goto fail;
    }

    /* Attempt to link the hitching post to the lockfile. */
    if ((rc = link(hitchfile, lockfile)) != 0) fstat(fd, &st);
    close(fd);
    fd = -1;
    unlink(hitchfile);

    /* Were we able to link the hitching post to the lockfile, and if we were,
     * did it have exactly 2 links when we were done? */
    if (rc != 0 && st.st_nlink != 2) {
        log_print(LOG_ERR, _("dotfile_lock(%s): unable to link hitching post to lock file: %m"), name);
        goto fail;
    }

    /* Success. */
    r = 0;

fail:
    if (lockfile) xfree(lockfile);
    if (hitchfile) xfree(hitchfile);
    if (fd != -1) close(fd);
    return r;
}

/* dotfile_unlock:
 * Unlock a file which has been locked using dotfile locking. Returns 0 on
 * success or -1 on failure.
 *
 * XXX We try to check that this is _our_ lockfile. Is this correct? */
int dotfile_unlock(const char *name) {
    char pidstr[16], pidstr2[16] = {0};
    char *lockfile = xmalloc(strlen(name) + 6);
    int fd = -1, r = -1;

    sprintf(pidstr, "%d\n", (int)getpid());

    if (!lockfile) goto fail;
    sprintf(lockfile, "%s.lock", name);

    /* Try to open the lockfile. */
    fd = open(lockfile, O_RDONLY);
    if (fd == -1) {
        log_print(LOG_ERR, "dotfile_unlock(%s): open: %m", name);
        goto fail;
    }

    if (read(fd, pidstr2, strlen(pidstr)) != strlen(pidstr)) {
        log_print(LOG_ERR, "dotfile_unlock(%s): read: %m", name);
        goto fail;
    }

    /* XXX is this correct? */
    if (strncmp(pidstr, pidstr2, strlen(pidstr)) != 0) {
        log_print(LOG_ERR, _("dotfile_unlock(%s): lockfile does not have our PID"), name);
        goto fail;
    }

    if (unlink(lockfile) == -1) {
        log_print(LOG_ERR, "dotfile_unlock(%s): unlink: %m", name);
        goto fail;
    }

    /* Success. */
    r = 0;

fail:
    if (lockfile) xfree(lockfile);
    if (fd != -1) close(fd);
    return r;
}
#endif /* WITH_DOTFILE_LOCKING */

#ifdef WITH_CCLIENT_LOCKING
/* cclient_steal_lock:
 * Attempt to steal a c-client lock (if any) applied to the file. Returns 0 on
 * success, or -1 on failure. This is fairly comedy, but it is good enough to
 * get PINE to get out of the way when necessary. */
int cclient_steal_lock(int fd) {
    struct stat st;
    char cclient_lockfile[64], other_pid[128] = {0};
    int fd_cc = -1, r = -1;
    pid_t p;
    
    if (fstat(fd, &st) == -1) return -1;
    sprintf(cclient_lockfile, "/tmp/.%lx.%lx", (unsigned long)st.st_dev, (unsigned long)st.st_ino);

    /* Although we never write to the lockfile, we need to open it RDWR since
     * we _may_ flock it in LOCK_EX mode.
     *
     * XXX exim lstats the /tmp/... file to ensure that it is not a symbolic
     * link. Since we don't actually write to the file, it is probably not
     * necessary to make this check. */
    fd_cc = open(cclient_lockfile, O_RDWR);
    if (fd_cc == -1) {
        if (errno == ENOENT) /* File did not exist; this is OK. */
            r = 0;
        else
            log_print(LOG_ERR, "cclient_steal_lock: open: %m");
        goto fail;
    }

    /* On most systems, the c-client library uses flock(2) to lock files. Some
     * systems do not have flock(2) (Solaris <cough>), or patch PINE to use
     * fcntl(2) locking (RedHat <cough>). */
#ifdef CCLIENT_USES_FCNTL
    if (fcntl_lock(fd_cc) == -1) {
#else
    if (flock_lock(fd_cc) == -1) {
#endif /* CCLIENT_USES_FLOCK */
        if (read(fd_cc, other_pid, sizeof(other_pid) - 1) == -1) {
            log_print(LOG_ERR, "cclient_steal_lock: read: %m");
            goto fail;
        }

        p = (pid_t)atoi(other_pid);
        if (p) {
            log_print(LOG_DEBUG, _("cclient_steal_lock: attempting to grab c-client lock from PID %d"), (int)p);
            kill(p, SIGUSR2);
        }

        sleep(2); /* Give PINE a moment to sort itself out. */

        /* Have another go. */
#ifdef CCLIENT_USES_FCNTL
        if (fcntl_lock(fd_cc) == -1)
#else
        if (flock_lock(fd_cc) == -1)
#endif /* CCLIENT_USES_FLOCK */
            /* No good. */
            log_print(LOG_ERR, _("cclient_steal_lock: failed to grab c-client lock from PID %d"), (int)p);
        else {
            /* It worked; unlink and close the c-client lockfile. */
            unlink(cclient_lockfile);
            r = 0;
        }
    } else {
        /* Managed to lock the file OK. */
        unlink(cclient_lockfile);
        r = 0;
    }
    
fail:
    if (fd_cc != -1) close(fd_cc);
    return r;
}
#endif /* WITH_CCLIENT_LOCKING */

#endif /* MBOX_BSD */
