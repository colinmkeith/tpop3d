/*
 * mailspool.c: Berkeley mailspool handling
 *
 * Copyright (c) 2000 Chris Lightfoot. All rights reserved.
 *
 * $Log$
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
#include <sys/types.h>

#include "mailspool.h"
#include "md5.h"

/* mailspool_new_from_file:
 * Open a file, lock it, and form an index of the messages in it.
 */
mailspool mailspool_new_from_file(const char *filename) {
    mailspool M;
    struct stat st;
    int i;
    
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
    
    /* FIXME Naive locking strategy. This will not work over NFS and should be
     * replaced by something using fcntl, which will, at least on modern
     * machines.
     */
    for (i = 0; i < MAILSPOOL_LOCK_TRIES; ++i) {
        M->fd = open(M->name, O_RDONLY);
        if (M->fd == -1) {
            syslog(LOG_ERR, "mailspool_new_from_file: %m");
            goto fail;
        }
        
        if (flock(M->fd, LOCK_EX | LOCK_NB) == 0) break;

        sleep(MAILSPOOL_LOCK_WAIT);
        close(M->fd);
        M->fd = -1;
    }

    if (M->fd == -1) {
        syslog(LOG_ERR, "mailspool_new_from_file: failed to lock %s: %m", filename);
        goto fail;
    }

    /* Build index of mailspool. */
    M->index = mailspool_build_index(M);
    if (!M->index) goto fail;

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
 * Build an index of a mailspool. Uses mmap(2) for speed.
 */
#define PAGESIZE        getpagesize()
#define NUMPAGES	8
#define BLOCKSIZE	(NUMPAGES * PAGESIZE)

vector mailspool_build_index(mailspool M) {
    char *filemem, *p, *q;
    size_t offset = 0, len;
    item *t;
    int i = 0;

    if (!M || M->fd == -1) return NULL;

    M->index = vector_new();
    if (!M->index) return NULL;

    filemem = mmap(0, len = BLOCKSIZE, PROT_READ, MAP_PRIVATE, M->fd, offset);
    if (filemem == MAP_FAILED) {
        vector_delete_free(M->index);
        syslog(LOG_ERR, "mailspool_build_index(%s): mmap: %m", M->name);
        close(M->fd);
        return NULL;
    }
    p = filemem - 2;

    do {
        size_t x, y;
        
	/* Extract all From lines from block */
	do {
	    p += 2;
	    q = (char*)memchr(p, '\n', len - (p - filemem));
	    if (q) {
                size_t o, l;
		o = offset + (p - filemem);
                l = q - p;
                
                vector_push_back(M->index, item_ptr(indexpoint_new(o, l, 0, p)));
                
		p = memstr(q, len - (q - filemem), "\n\nFrom ", 7);
	    }
	} while (p && q);

        y = BLOCKSIZE - PAGESIZE;
        
	if (q) x = q - filemem;
	else   x = p - filemem - 1;

	/* Find next block containing a complete From line */
	do {
	    if (munmap(filemem, len) == -1) {
                vector_delete_free(M->index);
                syslog(LOG_ERR, "mailspool_build_index(%s): munmap: %m", M->name);
                close(M->fd);
                return NULL;
            }
	    offset += y;
	    if (x > y)
		x -= y;
	    else
		x = 0;
            
	    y = PAGESIZE;
	    filemem = mmap(0, len = BLOCKSIZE, PROT_READ, MAP_PRIVATE, M->fd, offset);
	    if (filemem == MAP_FAILED) {
                vector_delete_free(M->index);
                syslog(LOG_ERR, "mailspool_build_index(%s): munmap: %m", M->name);
                close(M->fd);
                return NULL;
            } else {
		p = memstr(filemem + x, len - x, "\n\nFrom ", 7);
		if (p)
		    q = (char*)memchr(p + 2, '\n', len - (p + 2 - filemem));
	    }
	} while (offset < M->st.st_size && (!p || !q));
    } while (offset < M->st.st_size);

    munmap(filemem, len);

    /* OK, we're done, figure out the lengths */
    for (t = M->index->ary; t < M->index->ary + M->index->n_used - 1; ++t)
        ((indexpoint)t->v)->msglength = ((indexpoint)(t + 1)->v)->offset - ((indexpoint)t->v)->offset;
    ((indexpoint)t->v)->msglength = M->st.st_size - ((indexpoint)t->v)->offset;

    return M->index;
}

/* indexpoint_new:
 * Make an indexpoint, doing a hash of the data.
 */
indexpoint indexpoint_new(const size_t offset, const size_t length, const size_t msglength, const void *data) {
    indexpoint x;
    MD5_CTX ctx;

    x = (indexpoint)malloc(sizeof(struct _indexpoint));
    
    if (!x) return NULL;
    memset(x, 0, sizeof(struct _indexpoint));

    x->offset = offset;
    x->length = length;
    x->msglength = msglength;

    /* Compute MD5 */
    MD5Init(&ctx);
    MD5Update(&ctx, (unsigned char*)data, length);
    MD5Final(x->hash, &ctx);

    return x;
}
