/*
 * mailspool.c: Berkeley mailspool handling
 *
 * Copyright (c) 2000 Chris Lightfoot. All rights reserved.
 *
 * $Log$
 * Revision 1.4  2000/10/08 16:53:21  chris
 * Modified UID generation; also signal handler will always remove lockfile
 * on quit.
 *
 * Revision 1.3  2000/10/02 18:21:25  chris
 * Now supports modifying mailspools.
 *
 * Revision 1.2  2000/09/27 23:57:15  chris
 * Various changes.
 *
 * Revision 1.1  2000/09/26 22:23:36  chris
 * Initial revision
 *
 *
 */

static const char rcsid[] = "$Id$";

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

#include "connection.h"
#include "mailspool.h"
#include "md5.h"

/* File locking:
 * This is extremely simple, and therefore broken. In particular, it won't
 * work over NFS. Of course, IMO you'd be mad to want to put your mailspools
 * on an NFS-mounted filesystem anyway, but people do. To make this NFS-safe,
 * the obvious thing to do would be to steal the code from Exim which does it
 * (and is a contender for the prize in "most complicated code for something
 * which ought to be simple").
 * 
 * Both fcntl and .lock locking is done.
 *
 * Note also that we lock the whole mailspool for reading and writing. This is
 * pretty crap, but it makes it easier to make the program fast. In principle,
 * we could just lock the existing section of the file, so that the MTA could
 * deliver new messages on to the end of it, and then stat it when we were
 * about to apply changes in the UPDATE state, to see whether it had grown.
 */

/* file_lock:
 * Lock a mailspool file. Returns 1 on success or 0 on failure. We save the
 * name of the lockfile in a global variable accessible to the signal handler,
 * so that the lock can be undone even if a signal is received whilst the
 * mailspool is being processed.
 */
extern char *this_lockfile;

int file_lock(const int fd, const char *name) {
    struct flock fl = {0};
    char *lockfile = (char*)malloc(strlen(name) + 6);
    struct stat st;
    int fd2;

    fl.l_type   = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start  = 0;
    fl.l_len    = 0;
    
    if (!lockfile) return 0;
    sprintf(lockfile, "%s.lock", name);

    if (fcntl(fd, F_SETLK, &fl) == -1) {
        free(lockfile);
        return 0;
    }

    fl.l_type = F_UNLCK;

    /* Make lockfile; this is pretty naive, but that doesn't particularly
     * matter as we will not be running as root at this stage.
     */
    fd2 = open(lockfile, O_EXCL|O_CREAT|O_WRONLY); /* XXX NFS unsafe */
    this_lockfile = lockfile; /* Store this so that we ensure that mailspool is unlocked if a signal is received. */
    if (fd2 == -1) {
        syslog(LOG_ERR, "file_lock(%s): unable to create lockfile: %m", name);
        fcntl(fd, F_SETLK, &fl);
        return 0;
    }
    close(fd2);

    return 1;
}

/* file_unlock:
 * Unlock a mailspool file. Returns 1 on success or 0 on failure.
 */
int file_unlock(const int fd, const char *name) {
    struct flock fl = {0};
    char *lockfile = (char*)malloc(strlen(name) + 6);
    int ret = 1;

    fl.l_type   = F_UNLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start  = 0;
    fl.l_len    = 0;
 
    if (!lockfile) return 0;
    sprintf(lockfile, "%s.lock", name);

    if (unlink(lockfile) == -1) {
        free(lockfile);
        syslog(LOG_ERR, "file_unlock(%s): unlink: %m", name);
        ret = 0;
    }

    free(lockfile);

    if (fcntl(fd, F_SETLK, &fl) == -1) {
        syslog(LOG_ERR, "file_unlock(%s): fcntl: %m", name);
        ret = 0;
    }

    return ret;
}

/* mailspool_new_from_file:
 * Open a file, lock it, and form an index of the messages in it.
 */
mailspool mailspool_new_from_file(const char *filename) {
    mailspool M;
    struct stat st;
    int i;
    struct timeval tv1, tv2;
    double f;
    
    M = (mailspool)malloc(sizeof(struct _mailspool));
    if (!M) return NULL;

    memset(M, 0, sizeof(struct _mailspool));

    if (stat(filename, &(M->st)) == -1) {
        if (errno = ENOENT) {
            /* No mailspool */
            syslog(LOG_INFO, "mailspool_new_from_file: stat(%s): doesn't exist (is empty)", filename);
            M->name = strdup("/dev/null");
            M->fd = -1;
            M->isempty = 1;
            return M;
        } else {
            /* Oops. */
            syslog(LOG_INFO, "mailspool_new_from_file: stat(%s): %m", filename);
            goto fail;
        }
    } else M->name = strdup(filename);
    
    /* FIXME Naive locking strategy. */
    for (i = 0; i < MAILSPOOL_LOCK_TRIES; ++i) {
        M->fd = open(M->name, O_RDWR);
        if (M->fd == -1) {
            syslog(LOG_ERR, "mailspool_new_from_file: %m");
            goto fail;
        }
     
        if (file_lock(M->fd, M->name)) break;

        sleep(MAILSPOOL_LOCK_WAIT);
        close(M->fd);
        M->fd = -1;
    }

    if (M->fd == -1) {
        syslog(LOG_ERR, "mailspool_new_from_file: failed to lock %s: %m", filename);
        goto fail;
    }

    gettimeofday(&tv1, NULL);
    
    /* Build index of mailspool. */
    M->index = mailspool_build_index(M);
    if (!M->index) goto fail;

    gettimeofday(&tv2, NULL);
    f = (float)tv2.tv_sec + (1e-6 * tv2.tv_usec);
    f -= (float)tv1.tv_sec + (1e-6 * tv1.tv_usec);

    syslog(LOG_DEBUG, "mailspool_new_from_file: indexed mailspool %s (%d bytes) in %0.3lfs", filename, M->st.st_size, f);
    
    return M;

fail:
    if (M) {
        if (M->name) free(M->name);
        if (M->fd != -1) close(M->fd);
        free(M);
        return NULL;
    }
}

/* memstr:
 * Locate needly, of length n_len, in haystack, of length h_len, returning
 * NULL if it is not found.
 */
static char *memstr(const char *haystack, size_t h_len, const char *needle, size_t n_len)
{
    const char *p, *q;

    if (n_len > h_len)
	return NULL;

    p = (const char*) memchr(haystack, *needle, h_len - n_len);
    while (p) {
	if (!memcmp(p, needle, n_len))
	    return (char*)p;
	else
	    p = (const char*)memchr(p + 1, *needle, (haystack + h_len - n_len) - p - 1);
    }

    return NULL;
}

/* mailspool_build_index:
 * Build an index of a mailspool. Uses mmap(2) for speed. Assumes that
 * mailspools use only '\n' to indicate EOL.
 */
#define PAGESIZE        getpagesize()

vector mailspool_build_index(mailspool M) {
    char *filemem, *p, *q;
    size_t len, len2;
    item *t;
    int i = 0;

    if (!M || M->fd == -1) return NULL;

    M->index = vector_new();
    if (!M->index) return NULL;

    len = len2 = M->st.st_size;
    len += PAGESIZE - (len % PAGESIZE);
    filemem = mmap(0, len, PROT_READ, MAP_PRIVATE, M->fd, 0);
    if (filemem == MAP_FAILED) {
        syslog(LOG_ERR, "mailspool_build_index(%s): mmap: %m", M->name);
        vector_delete_free(M->index);
        close(M->fd);
        return NULL;
    }
    p = filemem - 2;

    /* Extract all From lines from file */
    do {
        p += 2;
        q = (char*)memchr(p, '\n', len - (p - filemem));
        if (q) {
            size_t o, l;
            o = p - filemem;
            l = q - p;

            vector_push_back(M->index, item_ptr(indexpoint_new(o, l, 0, p)));

            p = memstr(q, len2 - (q - filemem), "\n\nFrom ", 7);
        }
    } while (p);

    /* OK, we're done, figure out the lengths */
    for (t = M->index->ary; t < M->index->ary + M->index->n_used - 1; ++t)
        ((indexpoint)t->v)->msglength = ((indexpoint)(t + 1)->v)->offset - ((indexpoint)t->v)->offset;
    ((indexpoint)t->v)->msglength = M->st.st_size - ((indexpoint)t->v)->offset;

    /* We generate "unique" IDs by hashing the first 512 or so bytes of the
     * data in each message.
     */
    vector_iterate(M->index, t) {
        MD5_CTX ctx;
        indexpoint x = (indexpoint)t->v;
        size_t n = 512;

        if (n > x->msglength) n = x->msglength;
        
        /* Compute MD5 */
        MD5Init(&ctx);
        MD5Update(&ctx, (unsigned char*)filemem + x->offset, n);
        MD5Final(x->hash, &ctx);
    }

    munmap(filemem, len);
    
    return M->index;
}

/* indexpoint_new:
 * Make an indexpoint.
 */
indexpoint indexpoint_new(const size_t offset, const size_t length, const size_t msglength, const void *data) {
    indexpoint x;

    x = (indexpoint)malloc(sizeof(struct _indexpoint));
    
    if (!x) return NULL;
    memset(x, 0, sizeof(struct _indexpoint));

    x->offset = offset;
    x->length = length;
    x->msglength = msglength;

    return x;
}

/* mailspool_delete:
 * Delete a mailspool object (but don't actually delete messages in the
 * mailspool... the terminology is from C++ so it doesn't have to be logical).
 */
void mailspool_delete(mailspool m) {
    if (!m) return;

    if (m->index) vector_delete_free(m->index);

    if (m->name && m->fd != -1) {
        file_unlock(m->fd, m->name);
        close(m->fd);
    }

    if (m->name) free(m->name);
    
    free(m);
}

/* mailspool_send_message:
 * Send the header and n lines of the body of message number i from the
 * mailspool, escaping lines which begin . as required by RFC1939. Returns 1
 * on success or 0 on failure. The whole message is sent if n == -1.
 *
 * XXX Assumes that mailspools use only '\n' to indicate EOL.
 */
int mailspool_send_message(const mailspool M, int sck, const int i, int n) {
    char *filemem;
    size_t offset, length;
    indexpoint x;
    char *p, *q, *r;
    int A;
    
    if (!M) return 0;
    if (i < 0 || i >= M->index->n_used) return 0;
    x = (indexpoint)M->index->ary[i].v;

    offset = x->offset - (x->offset % PAGESIZE);
    length = (x->offset + x->msglength + PAGESIZE) ;
    length -= length % PAGESIZE;

    filemem = mmap(0, length, PROT_READ, MAP_PRIVATE, M->fd, offset);
    if (filemem == MAP_FAILED) {
        syslog(LOG_ERR, "mailspool_send_message: mmap: %m");
        return 0;
    }

    /* Find the beginning of the message headers */
    p = filemem + (x->offset % PAGESIZE);
    r = p + x->msglength;
    p += x->length + 1;

    /* Send the message headers */
    do {
        q = memchr(p, '\n', r - p);
        if (!q) q = r;
        errno = 0;
        if ((*p == '.' && write(sck, ".", 1) != 1) || write(sck, p, q - p) != (q - p) || write(sck, "\r\n", 2) != 2) {
            syslog(LOG_ERR, "mailspool_send_message: write: %m");
            munmap(filemem, length);
            return 0;
        }
        p = q + 1;
    } while (*p != '\n');
    ++p;

    errno = 0;
    if (write(sck, "\r\n", 2) != 2) {
        syslog(LOG_ERR, "mailspool_send_message: write: %m");
        munmap(filemem, length);
        return 0;
    }

    /* Now send the message itself */
    while (p < r && n) {
        if (n > 0) --n;

        q = memchr(p, '\n', r - p);
        if (!q) q = r;
        errno = 0;
        if ((*p == '.' && write(sck, ".", 1) != 1) || write(sck, p, q - p) != (q - p) || write(sck, "\r\n", 2) != 2) {
            syslog(LOG_ERR, "mailspool_send_message: write: %m");
            munmap(filemem, length);
            return 0;
        }
        p = q + 1;
    }

    if (munmap(filemem, length) == -1)
        syslog(LOG_ERR, "mailspool_send_message: munmap: %m");
    errno = 0;
    if ((A = write(sck, ".\r\n", 3)) != 3) {
        syslog(LOG_ERR, "mailspool_send_message: write: %d %m", A);
        return 0;
    } else return 1;
}

/* mailspool_apply_changes:
 * Apply deletions to a mailspool by mapping it and copying it in blocks.
 * Returns 1 on succes or 0 on failure.
 *
 * This is messy. Apart from the special cases of all messages to be deleted,
 * and no messages to be deleted, we need to cope with an arbitrary set of
 * messages being marked. Rather than using a temporary file and copying the
 * entire mailspool minus the marked messages, then unlinking the old one and
 * renaming the new one in its place, we mmap(2) the whole file and do some
 * memmove(3) magic to make the changes.
 *
 * Explanation: Clear sections represent sections not to be deleted, hatched
 * sections are parts which will be.
 *
 * I, J and K represent messages in the mailspool index.
 *
 *          +---+
 *          |   |
 *          |   |
 *    d --> +---+ <-- I beginning of
 *          |///|     section to be deleted
 *          |///|
 * d1 -->   |///|
 *          |///|
 *    s --> +---+ <-- J end of section
 *          |   |
 *          |   |
 *          +---+ <-- K beginning of      <-- I1
 *          |///|     next section to be
 *          |///|     deleted
 * s1 -->   +---+                         <-- J1
 *          |   |
 *          |   |
 *          |   |
 *          +---+                         <-- K1
 *          |///|
 *           ...
 *      
 * At this point, we can copy (K->offset - J->offset) bytes from J->offset
 * (s) to I->offset in the file (d).
 *
 * Now, we find the next set of ranges (I1, J1, K1 on diagram), and can
 * perform the next copy. s1 is J1->offset in the file, but d1 is
 * d + (K->offset - J->offset), to take account of the hole we made.
 * 
 * A special case occurs where the section to be deleted is at the end of the
 * file, at which point we can just ftruncate(2).
 */
int mailspool_apply_changes(mailspool M) {
    char *filemem, *s, *d;
    size_t len;
    item *I, *J, *K, *End;

    if (!M || M->fd == -1) return 0;

    if (M->numdeleted == 0)
        /* No messages deleted, do nothing. */
        return 1;
    else if (M->numdeleted == M->index->n_used) {
        /* All messages deleted, so just truncate file at zero. */
        if (ftruncate(M->fd, 0) == -1) {
            syslog(LOG_ERR, "mailspool_apply_changes(%s): ftruncate: %m", M->name);
            return 0;
        } else return 1;
    }

    /* We need to do something more complicated, so map the mailspool. */
    len = M->st.st_size;
    len += PAGESIZE - (len % PAGESIZE);
    filemem = mmap(0, len, PROT_WRITE | PROT_READ, MAP_SHARED, M->fd, 0);
    if (filemem == MAP_FAILED) {
        syslog(LOG_ERR, "mailspool_apply_changes(%s): mmap: %m", M->name);
        close(M->fd);
        return 0;
    }

    I = M->index->ary;
    End = M->index->ary + M->index->n_used;
    d = filemem;

    /* Find the first message to be deleted. */
    while (I < End && !((indexpoint)I->v)->deleted) ++I;
    if (I == End) {
        if (munmap(filemem, len) == -1) syslog(LOG_ERR, "mailspool_send_message: munmap: %m");
        syslog(LOG_ERR, "mailspool_apply_changes(%s): inconsistency in mailspool data", M->name);
        return 0;
    }
    d = filemem + ((indexpoint)I->v)->offset;
    
    do {
        /* Find the first non-deleted message after this block. */
        J = I;
        while (J < End && ((indexpoint)J->v)->deleted) ++J;
        if (J == End) break;
        else {
            /* Find the end of this chunk. */
            size_t copylen = 0;
            s = filemem + ((indexpoint)J->v)->offset;
            K = J;
            while (K < End && !((indexpoint)K->v)->deleted) copylen += ((indexpoint)(K++)->v)->msglength;

            /* Not every machine has a working memmove(3) (allows overlapping
             * memory areas). If yours doesn't, you should get a better one ;)
             */
            syslog(LOG_ERR, "filemem %p s %p d %p copylen %d", filemem, s, d, copylen);
            memmove(d, s, copylen);
            d += copylen;
        }

        I = K;
    } while (I < End);

    /* Truncate the very end. */
    if (ftruncate(M->fd, d - filemem) == -1) {
        syslog(LOG_ERR, "mailspool_apply_changes(%s): ftruncate: %m", M->name);
        if (munmap(filemem, len) == -1) syslog(LOG_ERR, "mailspool_send_message: munmap: %m");
        return 0;
    }
    
    /* Done, unmap the file. */
    if (munmap(filemem, len) == -1) {
        syslog(LOG_ERR, "mailspool_send_message: munmap: %m");
        return 0;
    }

    return 1;
}

