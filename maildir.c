/*
 *  maildir.c:
 *  Qmail-style maildir support for tpop3d.
 *
 *  Copyright (c) 2001 Paul Makepeace (realprogrammers.com).
 *  All rights reserved.
 * 
 */
 
#ifdef HAVE_CONFIG_H
#include "configuration.h"
#endif /* HAVE_CONFIG_H */

#ifdef MBOX_MAILDIR

static const char rcsid[] = "$Id$";

#include <sys/types.h>

#include <dirent.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>
#include <utime.h>
#include <time.h>

#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>

#include "config.h"
#include "connection.h"
#include "mailbox.h"
#include "util.h"
#include "vector.h"

/*
 * Although maildir is a locking-free mailstore, we optionally support the
 * exclusive locking of maildirs so that we can implement the RFC1939
 * semantics where POP3 sessions are exclusive. To do this we create a lock
 * directory called .poplock in the root of the maildir. This is convenient
 * because mkdir(2) is atomic, even on NFS.
 */

/* MAILDIR_LOCK_LIFETIME
 * How long a maildir lock lasts if it is never unlocked. */
#define MAILDIR_LOCK_LIFETIME   1800

/* maildir_lock DIRECTORY
 * Attempt to atomically create a .poplock lock directory in DIRECTORY. Returns
 * 1 on success or 0 on failure. If such a directory exists and is older than
 * MAILDIR_LOCK_LIFETIME, we will update the time in it, claiming the lock
 * ourselves. */
static int maildir_lock(const char *dirname) {
    char *lockdirname = NULL;
    int ret = 0;

    lockdirname = xmalloc(strlen(dirname) + sizeof("/.poplock"));
    sprintf(lockdirname, "%s/.poplock", dirname);
    if (mkdir(lockdirname, 0777) == -1) {
        if (errno == EEXIST) {
            /* 
             * Already locked. Now we have a problem, because we can't
             * atomically discover the creation time of the directory and
             * update it. For the moment, just do this the nonatomic way and
             * hope for the best. It's not too serious since we now react
             * properly in the case that the message has been deleted by
             * another user.
             */
            struct stat st;
            if (stat(lockdirname, &st) == -1)
                log_print(LOG_ERR, _("maildir_lock: %s: could not stat .poplock directory: %m"), dirname);
            else if (st.st_atime < time(NULL) - MAILDIR_LOCK_LIFETIME) {
                /* XXX Race condition here. */
                if (utime(lockdirname, NULL) == -1)
                    log_print(LOG_ERR, _("maildir_lock: %s: could not update access time on .poplock directory: %m"), dirname);
                else {
                    log_print(LOG_WARNING, _("maildir_lock: %s: grabbed stale (age %d:%02d) lock"), dirname, (int)(time(NULL) - st.st_atime) / 60, (int)(time(NULL) - st.st_atime) % 60);
                    ret = 1;
                }
            }
        } else
            log_print(LOG_ERR, _("maildir_lock: %s: could not create .poplock directory: %m"), dirname);
    } else
        ret = 1;

    if (lockdirname)
        xfree(lockdirname);
    return ret;
}

/* maildir_update_lock DIRECTORY
 * Update the access time on DIRECTORY. */
static void maildir_update_lock(const char *dirname) {
    static time_t last_updated_lock;
    if (last_updated_lock < time(NULL) - 60) {
        char *lockdirname = NULL;
        lockdirname = xmalloc(strlen(dirname) + sizeof("/.poplock"));
        sprintf(lockdirname, "%s/.poplock", dirname);
        utime(lockdirname, NULL);
        xfree(lockdirname);
        last_updated_lock = time(NULL);
    }
}

/* maildir_unlock DIRECTORY
 * Remove any .poplock lock directory in DIRECTORY. */
static void maildir_unlock(const char *dirname) {
    char *lockdirname;
    lockdirname = xmalloc(strlen(dirname) + sizeof("/.poplock"));
    sprintf(lockdirname, "%s/.poplock", dirname);
    rmdir(lockdirname); /* Nothing we can do if this fails. */
    xfree(lockdirname);
}


/* maildir_make_indexpoint:
 * Make an indexpoint to put in a maildir. */
static void maildir_make_indexpoint(struct indexpoint *m, const char *filename, off_t size, time_t mtime) {
    memset(m, 0, sizeof(struct indexpoint));

    m->filename = xstrdup(filename);
    if (!m->filename) {
        return;
    }
    m->offset = 0;    /* not used */
    m->length = 0;    /* "\n\nFrom " delimiter not used */
    m->deleted = 0;
    m->msglength = size;

    /* In previous versions of tpop3d, the first 16 characters of the file name
     * of a maildir message were used to form a unique ID. Unfortunately, this
     * is not a good strategy, especially now that time_t's are 10 characters
     * long. So now we form an MD5 hash of the file name; obviously, these
     * unique IDs are not compatible with the old ones, so optionally you can
     * retain the old scheme by replacing the following line with
     *     strncpy(m->hash, filename+4, sizeof(m->hash));
     */
    md5_digest(filename + 4, strcspn(filename + 4, ":"), m->hash); /* +4: skip cur/ or new/ subdir; ignore flags at end. */
    
    m->mtime = mtime;
}

/* maildir_build_index MAILDIR SUBDIR TIME
 * Build an index of the MAILDIR; SUBDIRis one of cur, tmp or new; TIME is the
 * time at which the operation started, used to ignore messages delivered
 * during processes. Returns 0 on success, -1 otherwise. */
int maildir_build_index(mailbox M, const char *subdir, time_t time) {
    DIR *dir;
    struct dirent *d;

    if (!M) return -1;

    dir = opendir(subdir);
    if (!dir) {
        log_print(LOG_ERR, "maildir_build_index: opendir(%s): %m", subdir);
        return -1;
    }
    
    while ((d = readdir(dir))) {
        struct stat st;
        char *filename;
        
        if (d->d_name[0] == '.') continue;
        filename = xmalloc(strlen(subdir) + strlen(d->d_name) + 2);
        sprintf(filename, "%s/%s", subdir, d->d_name);
        if (!filename) return -1;
        if (stat(filename, &st) == 0 && st.st_mtime < time) {
            /* These get sorted by mtime later. */
            struct indexpoint pt;
            maildir_make_indexpoint(&pt, filename, st.st_size, st.st_mtime);
            mailbox_add_indexpoint(M, &pt);
            /* Accumulate size of messages. */
            M->totalsize += st.st_size;
        }
        xfree(filename);
    }
    closedir(dir);
    
    if (d) {
        log_print(LOG_ERR, "maildir_build_index: readdir(%s): %m", subdir);
        return -1;
    }

#ifdef IGNORE_CCLIENT_METADATA
#warning IGNORE_CCLIENT_METADATA not supported with maildir.
#endif /* IGNORE_CCLIENT_METADATA */

    return 0;
}

/* maildir_sort_callback A B
 * qsort(3) callback for ordering messages in a maildir. */
int maildir_sort_callback(const void *a, const void *b) {
    const struct indexpoint *A = a, *B = b;
    return A->mtime - B->mtime;
}

/* maildir_new DIRECTORY
 * Create a mailbox object from the named DIRECTORY. */
mailbox maildir_new(const char *dirname) {
    mailbox M, failM = NULL;
    struct timeval tv1, tv2;
    float f;
 
    alloc_struct(_mailbox, M);
    
    M->delete = maildir_delete;                 /* generic destructor */
    M->apply_changes = maildir_apply_changes;
    M->sendmessage = maildir_sendmessage;

    /* Allocate space for the index. */
    M->index = (struct indexpoint*)xcalloc(32, sizeof(struct indexpoint));
    M->size = 32;
    
    if (chdir(dirname) == -1) {
        if (errno == ENOENT) failM = MBOX_NOENT;
        else log_print(LOG_ERR, "maildir_new: chdir(%s): %m", dirname);
        goto fail;
    } else
        M->name = xstrdup(dirname);

    /* Optionally, try to lock the maildir. */
    if (config_get_bool("maildir-exclusive-lock") && !maildir_lock(M->name)) {
        log_print(LOG_INFO, _("maildir_new: %s: couldn't lock maildir"), dirname);
        goto fail;
    }
    
    gettimeofday(&tv1, NULL);
    
    /* Build index of maildir. */
    if (maildir_build_index(M, "new", tv1.tv_sec) != 0) goto fail;
    if (maildir_build_index(M, "cur", tv1.tv_sec) != 0) goto fail;

    /* Now sort the messages. */
    qsort(M->index, M->num, sizeof(struct indexpoint), maildir_sort_callback);

    gettimeofday(&tv2, NULL);
    f = (float)(tv2.tv_sec - tv1.tv_sec) + 1e-6 * (float)(tv2.tv_usec - tv1.tv_usec);
    log_print(LOG_DEBUG, "maildir_new: scanned maildir %s (%d messages) in %0.3fs", dirname, (int)M->num, f);
    
    return M;

fail:
    if (M) {
        if (M->name) xfree(M->name);
        if (M->index) xfree(M->index);
        xfree(M);
    }
    return failM;
}

/* maildir_delete MAILDIR
 * Destructor for MAILDIR; this does nothing maildir-specific unless maildir
 * locking is enabled, in which case we must unlock it. */
void maildir_delete(mailbox M) {
    if (config_get_bool("maildir-exclusive-lock"))
        maildir_unlock(M->name);
    mailbox_delete(M);
}

/* maildir_open_message_file MESSAGE
 * Return a file descriptor on the file associated with MESSAGE. If it has
 * changed name since then, we try to find the file and update MESSAGE. If we
 * can't find the MESSAGE, return -1. */
static int open_message_file(struct indexpoint *m) {
    int fd;
    DIR *d;
    struct dirent *de;
    size_t msgnamelen;

    fd = open(m->filename, O_RDONLY);
    if (fd != -1)
        return fd;
    
    /* 
     * Where's that message?
     */
    
    /* Possibility 1: message was in new/, and is now in cur/ with a :2,S
     * suffix. */
    if (strncmp(m->filename, "new/", 4)) {
        char *name;
        name = xmalloc(strlen(m->filename) + sizeof(":2,S"));
        sprintf(name, "cur/%s:2,S", m->filename + 4);
        if ((fd = open(name, O_RDONLY)) != -1) {
            /* We win! */
            xfree(m->filename);
            m->filename = name;
            return fd;
        } else if (errno != ENOENT) {
            /* Bad news. */
            log_print(LOG_ERR, "maildir_open_message_file: %s: %m", name);
            xfree(name);
            return -1;
        }
    }

    /* Possibility 2: message is now in cur with some random suffix. This is
     * really bad, because we need to rescan the whole maildir. But this
     * shouldn't happen very often. */

    /* Figure out the name of the message. */
    msgnamelen = strcspn(m->filename + 4, ":");
    
    if (!(d = opendir("cur"))) {
        log_print(LOG_ERR, "maildir_open_message_file: cur: %m");
        return -1;
    }

    while ((de = readdir(d))) {
        /* Compare base name of this message against the new message. */
        if (strncmp(de->d_name, m->filename + 4, msgnamelen) == 0
            && (de->d_name[msgnamelen] == ':' || de->d_name[msgnamelen] == 0)) {
            char *name;
            name = xmalloc(strlen(de->d_name) + sizeof("cur/"));
            sprintf(name, "cur/%s", de->d_name);
            if ((fd = open(name, O_RDONLY)) != -1) {
                closedir(d);
                xfree(m->filename);
                m->filename = name;
                return fd;
            } else {
                /* Either something's gone wrong or the message has just been
                 * moved or deleted. Just give up at this point. */
                closedir(d);
                xfree(name);
                return -1;
            }
        }
    }

    log_print(LOG_ERR, _("maildir_open_message_file: %s: can't find message"), m->filename);

    /* Message must have been deleted. */
    return -1;
}

/* maildir_sendmessage MAILDIR CONNECTION MSGNUM LINES
 * Send a +OK response and the header and the given number of LINES of the body
 * of message number MSGNUM from MAILDIR escaping lines which begin . as
 * required by RFC1939, or, if it cannot, a -ERR error response.  Returns 1 on
 * is -1. Sends a +OK / -ERR message in front of the message itself. Note that
 * the maildir specification says that messages use only `\n' to indicate EOL,
 * though some extended formats don't. We assume that the specification is
 * obeyed. It's possible that the message will have moved or been deleted under
 * us, in which case we make some effort to find the new version. */
int maildir_sendmessage(const mailbox M, connection c, const int i, int n) {
    struct indexpoint *m;
    int fd, status;
    
    if (!M || i < 0 || i >= M->num) {
        /* Shouldn't happen. */
        connection_sendresponse(c, 0, _("Unable to send that message"));
        return -1;
    }

    if (config_get_bool("maildir-exclusive-lock"))
        maildir_update_lock(M->name);

    m = M->index +i;
    
    if ((fd = open_message_file(m)) == -1) {
        connection_sendresponse(c, 0, _("Can't send that message; it may have been deleted by a concurrent session"));
        log_print(LOG_ERR, "maildir_sendmessage: unable to send message %d", i + 1);
        return -1;
    }
    
    status = connection_sendmessage(c, fd, 0 /* offset */, 0 /* skip */, m->msglength, n);
    close(fd);

    return status;
}

/* maildir_apply_changes MAILDIR
 * Apply deletions to a maildir. */
int maildir_apply_changes(mailbox M) {
    struct indexpoint *m;
    if (!M) return 1;

    for (m = M->index; m < M->index + M->num; ++m) {
        if (m->deleted) {
            if (unlink(m->filename) == -1)
                log_print(LOG_ERR, "maildir_apply_changes: unlink(%s): %m", m->filename);
                /* Warn but proceed anyway. */
        } else {
            /* Mark message read. */
            if (strncmp(m->filename, "new/", 4) == 0) {
                char *cur;
                cur = xmalloc(strlen(m->filename) + 5);
                sprintf(cur, "cur/%s:2,S", m->filename + 4); /* Set seen flag */
                rename(m->filename, cur);    /* doesn't matter if it can't */
                xfree(cur);
            }
        }
    }

    return 1;
}

#endif /* MBOX_MAILDIR */
