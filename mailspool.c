/*
 * mailspool.c:
 * Berkeley mailspool handling.
 *
 * Note that this makes _no_ attempt to handle the awful SysVism of not
 * quoting /^From / in body text and attempting to use Content-Length to
 * figure out where messages start and end.
 *
 * See http://home.netscape.com/eng/mozilla/2.0/relnotes/demo/content-length.html
 *
 * This also, optionally, allows the metadata stored into mailspools (why,
 * Washington University, why?) by PINE to be ignored. This means that those
 * who use PINE locally and a POP3 client remotely will not find themselves
 * continuously downloading copies of "DON'T DELETE THIS MESSAGE -- ...".
 *
 * Copyright (c) 2001 Chris Lightfoot. All rights reserved.
 *
 */

static const char rcsid[] = "$Id$";

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <sys/file.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/utsname.h>

#include "connection.h"
#include "locks.h"
#include "mailspool.h"
#include "md5.h"
#include "util.h"

/* file_unlock:
 * Unlock a mailspool file. Returns 1 on success or 0 on failure.
 */
int file_unlock(const int fd, const char *name) {
    int r = 1;
 #ifdef WITH_FCNTL_LOCKING
    if (fcntl_unlock(fd) == -1) r = 0;
#endif

#ifdef WITH_FLOCK_LOCKING
    if (flock_unlock(fd) == -1) r = 0;
#endif

#ifdef WITH_DOTFILE_LOCKING
    if (name && dotfile_unlock(name) == -1) r = 0;
#endif

    return r;
}

/* file_lock:
 * Lock a mailspool file. Returns 1 on success or 0 on failure. This uses
 * whatever locking strategies the user has selected with compile-time
 * definitions.
 */
int file_lock(const int fd, const char *name) {
    int l_fcntl, l_flock, l_dotfile;
    l_fcntl = l_flock = l_dotfile = 0;

#ifdef WITH_FCNTL_LOCKING
    if (fcntl_lock(fd) == -1) goto fail;
    else l_fcntl = 1;
#endif
#ifdef WITH_FLOCK_LOCKING
    if (flock_lock(fd) == -1) goto fail;
    else l_flock = 1;
#endif
#ifdef WITH_DOTFILE_LOCKING
    if (dotfile_lock(name) == -1) goto fail;
    else l_dotfile = 1;
#endif
#ifdef WITH_CCLIENT_LOCKING
    if (cclient_steal_lock(fd) == -1) goto fail;
#endif

    return 1;
    
fail:
#ifdef WITH_FCNTL_LOCKING
    if (l_fcntl) fcntl_unlock(fd);
#endif
#ifdef WITH_FLOCK_LOCKING
    if (l_flock) flock_unlock(fd);
#endif
#ifdef WITH_DOTFILE_LOCKING
    if (l_dotfile) dotfile_unlock(name);
#endif
    
    return 0;
}

/* mailspool_new_from_file:
 * Open a file, lock it, and form an index of the messages in it.
 */
mailspool mailspool_new_from_file(const char *filename) {
    mailspool M;
    int i;
    struct timeval tv1, tv2;
    float f;
    
    M = (mailspool)malloc(sizeof(struct _mailspool));
    if (!M) return NULL;

    memset(M, 0, sizeof(struct _mailspool));

    if (stat(filename, &(M->st)) == -1) {
        if ( errno == ENOENT ) {
            /* No mailspool */
            print_log(LOG_INFO, "mailspool_new_from_file: stat(%s): doesn't exist (is empty)", filename);
            M->name = strdup("/dev/null");
            M->fd = -1;
            M->isempty = 1;
            M->index = vector_new();
            return M;
        } else {
            /* Oops. */
            print_log(LOG_INFO, "mailspool_new_from_file: stat(%s): %m", filename);
            goto fail;
        }
    } else M->name = strdup(filename);
    
    /* FIXME Naive locking strategy. */
    for (i = 0; i < MAILSPOOL_LOCK_TRIES; ++i) {
        M->fd = open(M->name, O_RDWR);
        if (M->fd == -1) {
            print_log(LOG_ERR, "mailspool_new_from_file: %m");
            goto fail;
        }
     
        if (file_lock(M->fd, M->name)) break;

        sleep(MAILSPOOL_LOCK_WAIT);
        close(M->fd);
        M->fd = -1;
    }

    if (M->fd == -1) {
        print_log(LOG_ERR, "mailspool_new_from_file: failed to lock %s: %m", filename);
        goto fail;
    }

    gettimeofday(&tv1, NULL);
    
    /* Build index of mailspool. */
    M->index = mailspool_build_index(M);
    if (!M->index) goto fail;

    gettimeofday(&tv2, NULL);
    f = (float)(tv2.tv_sec - tv1.tv_sec) + 1e-6 * (float)(tv2.tv_usec - tv1.tv_usec);
    print_log(LOG_DEBUG, "mailspool_new_from_file: indexed mailspool %s (%d bytes) in %0.3fs", filename, (int)M->st.st_size, f);
    
    return M;

fail:
    if (M) {
        if (M->name) free(M->name);
        if (M->fd != -1) close(M->fd);
        free(M);
    }
    return NULL;
}

/* memstr:
 * Locate needly, of length n_len, in haystack, of length h_len, returning
 * NULL if it is not found.
 */
static char *memstr(const char *haystack, size_t h_len, const char *needle, size_t n_len)
{
    const char *p;

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

    if (!M || M->fd == -1) return NULL;

    M->index = vector_new();
    if (!M->index) return NULL;

    len = len2 = M->st.st_size;

    if (len < 16) return M->index; /* Mailspool doesn't contain any messages. */

    len += PAGESIZE - (len % PAGESIZE);
    filemem = mmap(0, len, PROT_READ, MAP_PRIVATE, M->fd, 0);
    if (filemem == MAP_FAILED) {
        print_log(LOG_ERR, "mailspool_build_index(%s): mmap: %m", M->name);
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
        } else break;
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

#ifdef IGNORE_CCLIENT_METADATA
    /* Optionally, check whether the first message in the mailspool is
     * internal data used by c-client; such messages contain the following
     * headers:
     *
     *  Subject: DON'T DELETE THIS MESSAGE -- FOLDER INTERNAL DATA
     *  X-IMAP: <some numbers>
     */
    if (M->index->n_used >= 1) {
        p = memstr(filemem, ((indexpoint)M->index->ary->v)->msglength, "\n\n", 2);
        if (p) {
            const char hdr1[] = "\nX-IMAP: ", hdr2[] = "Subject: DON'T DELETE THIS MESSAGE -- FOLDER INTERNAL DATA\n";
            if (memstr(filemem, p - filemem, hdr1, strlen(hdr1)) && memstr(filemem, p - filemem, hdr2, strlen(hdr2))) {
                print_log(LOG_DEBUG, "mailspool_build_index(%s): skipping c-client metadata", M->name);
                free(M->index->ary->v);
                vector_remove(M->index, M->index->ary);
            }
        }
    }
#endif /* IGNORE_CCLIENT_METADATA */

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

    if (m->name || m->fd != -1) {
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
#define try_write(a, b, c)      (xwrite((a), (b), (c)) == (c))

int mailspool_send_message(const mailspool M, int sck, const int i, int n) {
    char *filemem;
    size_t offset, length;
    indexpoint x;
    char *p, *q, *r;

    if (!M) return 0;
    if (i < 0 || i >= M->index->n_used) return 0;
    x = (indexpoint)M->index->ary[i].v;

    offset = x->offset - (x->offset % PAGESIZE);
    length = (x->offset + x->msglength + PAGESIZE) ;
    length -= length % PAGESIZE;

    filemem = mmap(0, length, PROT_READ, MAP_PRIVATE, M->fd, offset);
    if (filemem == MAP_FAILED) {
        print_log(LOG_ERR, "mailspool_send_message: mmap: %m");
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
        /* Escape a leading ., if present. */
        if (*p == '.' && !try_write(sck, ".", 1)) goto write_failure;
        /* Send line itself. */
        if (!try_write(sck, p, q - p) || !try_write(sck, "\r\n", 2))
            goto write_failure;
        p = q + 1;
    } while (*p != '\n');
    ++p;

    errno = 0;
    if (!try_write(sck, "\r\n", 2)) {
        print_log(LOG_ERR, "mailspool_send_message: write: %m");
        munmap(filemem, length);
        return 0;
    }
    
    /* Now send the message itself */
    while (p < r && n) {
        if (n > 0) --n;

        q = memchr(p, '\n', r - p);
        if (!q) q = r;
        errno = 0;

        /* Escape a leading ., if present. */
        if (*p == '.' && !try_write(sck, ".", 1)) goto write_failure;
        /* Send line itself. */
        if (!try_write(sck, p, q - p) || !try_write(sck, "\r\n", 2))
            goto write_failure;

        p = q + 1;
    }
    if (munmap(filemem, length) == -1)
        print_log(LOG_ERR, "mailspool_send_message: munmap: %m");
    
    errno = 0;
    if (!try_write(sck, ".\r\n", 3)) {
        print_log(LOG_ERR, "mailspool_send_message: write: %m");
        return 0;
    } else return 1;

write_failure:
    print_log(LOG_ERR, "mailspool_send_message: write: %m");
    munmap(filemem, length);
    return 0;
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

    if (!M || M->fd == -1) return 1;

    if (M->numdeleted == 0)
        /* No messages deleted, do nothing. */
        return 1;
    else if (M->numdeleted == M->index->n_used) {
        /* All messages deleted, so just truncate file at the beginning of the
         * first message.
         */
        if (ftruncate(M->fd, ((indexpoint)M->index->ary[0].v)->offset) == -1) {
            print_log(LOG_ERR, "mailspool_apply_changes(%s): ftruncate: %m", M->name);
            return 0;
        } else return 1;
    }

    /* We need to do something more complicated, so map the mailspool. */
    len = M->st.st_size;
    len += PAGESIZE - (len % PAGESIZE);
    filemem = mmap(0, len, PROT_WRITE | PROT_READ, MAP_SHARED, M->fd, 0);
    if (filemem == MAP_FAILED) {
        print_log(LOG_ERR, "mailspool_apply_changes(%s): mmap: %m", M->name);
        close(M->fd);
        return 0;
    }

    I = M->index->ary;
    End = M->index->ary + M->index->n_used;
    d = filemem;

    /* Find the first message to be deleted. */
    while (I < End && !((indexpoint)I->v)->deleted) ++I;
    if (I == End) {
        if (munmap(filemem, len) == -1) print_log(LOG_ERR, "mailspool_send_message: munmap: %m");
        print_log(LOG_ERR, "mailspool_apply_changes(%s): inconsistency in mailspool data", M->name);
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
            memmove(d, s, copylen);
            d += copylen;
        }

        I = K;
    } while (I < End);

    /* Truncate the very end. */
    if (ftruncate(M->fd, d - filemem) == -1) {
        print_log(LOG_ERR, "mailspool_apply_changes(%s): ftruncate: %m", M->name);
        if (munmap(filemem, len) == -1) print_log(LOG_ERR, "mailspool_send_message: munmap: %m");
        return 0;
    }
    
    /* Done, unmap the file. */
    if (munmap(filemem, len) == -1) {
        print_log(LOG_ERR, "mailspool_send_message: munmap: %m");
        return 0;
    }

    return 1;
}

