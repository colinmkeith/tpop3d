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

#include <sys/types.h>     /* u_int_* for dirent.h */
#include <dirent.h>        /* DIR, etc */
#include <syslog.h>        /* LOG_* */
#include <unistd.h>        /* chdir() */
#include <string.h>        /* strdup() */
#include <stdlib.h>
#include <sys/fcntl.h>     /* O_RDONLY */
#include <sys/time.h>
#include <stdio.h>         /* rename() */
#include <errno.h>

#include "mailbox.h"
#include "util.h"
#include "vector.h"

/* maildir_make_indexpoint:
 * Make an indexpoint to put in a maildir.
 */
static void maildir_make_indexpoint(struct indexpoint *m, const char *filename, off_t size, time_t mtime) {
    memset(m, 0, sizeof(struct indexpoint));

    m->filename = strdup(filename);
    if (!m->filename) {
        return;
    }
    m->offset = 0;    /* not used */
    m->length = 0;    /* "\n\nFrom " delimiter not used */
    m->deleted = 0;
    m->msglength = size;
    /* XXX this could break uniqueness, though in practice this is unlikely. */
    strncpy(m->hash, filename+4, sizeof(m->hash));    /* +4: skip cur/ or new/ subdir */
    
    m->mtime = mtime;
}

/* maildir_build_index:
 * Build an index of a maildir. subdir is one of cur, tmp or new; time is the
 * time at which the operation started, used to ignore messages delivered
 * during processes. Returns 0 on success, -1 otherwise.
 */
int maildir_build_index(mailbox M, const char *subdir, time_t time) {
    DIR *dir;
    struct dirent *d;

    if (!M) return -1;

    dir = opendir(subdir);
    if (!dir) {
        print_log(LOG_ERR, "maildir_build_index: opendir(%s): %m", subdir);
        return -1;
    }
    
    while ((d = readdir(dir))) {
        struct stat st;
        char *filename;
        
        if (d->d_name[0] == '.') continue;
        filename = (char*)malloc(strlen(subdir) + strlen(d->d_name) + 2);
        sprintf(filename, "%s/%s", subdir, d->d_name);
        if (!filename) return -1;
        if (stat(filename, &st) == 0 && st.st_mtime < time) {
            /* These get sorted by mtime later. */
            struct indexpoint pt;
            maildir_make_indexpoint(&pt, filename, st.st_size, st.st_mtime);
            mailbox_add_indexpoint(M, &pt);
            /* Hack: accumulate size of messages. */
            M->st.st_size += st.st_size;
        }
        free(filename);
    }
    closedir(dir);
    
    if (d) {
        print_log(LOG_ERR, "maildir_build_index: readdir(%s): %m", subdir);
        return -1;
    }

#ifdef IGNORE_CCLIENT_METADATA
#warning IGNORE_CCLIENT_METADATA not supported with maildir.
#endif /* IGNORE_CCLIENT_METADATA */

    return 0;
}

/* maildir_sort_callback:
 * qsort(3) callback for ordering messages in a maildir.
 */
int maildir_sort_callback(const void *a, const void *b) {
    const struct indexpoint *A = a, *B = b;
    return A->mtime - B->mtime;
}

/* maildir_new:
 * Create a mailbox object from a maildir.
 */
mailbox maildir_new(const char *dirname) {
    mailbox M, failM = NULL;
    struct timeval tv1, tv2;
    float f;
    
    M = (mailbox)malloc(sizeof(struct _mailbox));
    if (!M) return NULL;
    memset(M, 0, sizeof(struct _mailbox));
    
    M->delete = mailbox_delete;                 /* generic destructor */
    M->apply_changes = maildir_apply_changes;
    M->send_message = maildir_send_message;

    /* Allocate space for the index. */
    M->index = (struct indexpoint*)calloc(32, sizeof(struct indexpoint));
    M->size = 32;
    
    if (chdir(dirname) == -1) {
        if (errno == ENOENT) failM = MBOX_NOENT;
        else print_log(LOG_ERR, "maildir_new: chdir(%s): %m", dirname);
        goto fail;
    } else {
        if(!(M->name = strdup(dirname))) {
            print_log(LOG_ERR, "maildir_new: strdup: %m");
            goto fail;
        }
    }
    
    gettimeofday(&tv1, NULL);
    
    /* Build index of maildir. */
    if (maildir_build_index(M, "new", tv1.tv_sec) != 0) goto fail;
    if (maildir_build_index(M, "cur", tv1.tv_sec) != 0) goto fail;

    /* Now sort the messages. */
    qsort(M->index, M->num, sizeof(struct indexpoint), maildir_sort_callback);

    gettimeofday(&tv2, NULL);
    f = (float)(tv2.tv_sec - tv1.tv_sec) + 1e-6 * (float)(tv2.tv_usec - tv1.tv_usec);
    print_log(LOG_DEBUG, "maildir_new: scanned maildir %s (%d messages) in %0.3fs", dirname, (int)M->num, f);
    
    return M;

fail:
    if (M) {
        if (M->name) free(M->name);
        free(M);
    }
    return failM;
}

/* maildir_send_message:
 * Send the header and n lines of the body of message number i from the
 * maildir, escaping lines which begin . as required by RFC1939. Returns 1
 * on success or 0 on failure. The whole message is sent if n == -1.
 *
 * XXX Assumes that maildirs use only '\n' to indicate EOL.
 */
int maildir_send_message(const mailbox M, int sck, const int i, int n) {
    struct indexpoint *m;
    int fd, status;
    
    if (!M) return 0;
    if (i < 0 || i >= M->num) return 0;
    m = M->index +i;
    fd = open(m->filename, O_RDONLY);
    if (fd == -1) {
        print_log(LOG_ERR, "maildir_send_message: open(%s): %m", m->filename);
        return 0;
    }
    print_log(LOG_INFO, "maildir_send_message: sending message %d (%s) size %d bytes", i+1, m->filename, m->msglength);
    status = write_file(fd, sck, 0 /* offset */, 0 /* skip */, m->msglength, n);
    close(fd);

    return status;
}

/* maildir_apply_changes:
 * Apply deletions to a maildir.
 */
int maildir_apply_changes(mailbox M) {
    struct indexpoint *m;
    if (!M) return 1;

    for (m = M->index; m < M->index + M->num; ++m) {
        if (m->deleted) {
            if (unlink(m->filename) == -1) {
                print_log(LOG_ERR, "maildir_apply_changes: unlink(%s): %m", m->filename);
                return 0;
            }
        } else {
            /* Mark message read. */
            if (strncmp(m->filename, "new/", 4) == 0) {
                char *cur;
                cur = (char*)malloc(6 + strlen(m->filename) - 4);
                sprintf(cur, "cur/%s", m->filename + 4);
                if (!cur) return 0;
                rename(m->filename, cur);    /* doesn't matter if it can't */
                free(cur);
            }
        }
    }

    return 1;
}

#endif /* MBOX_MAILDIR */
