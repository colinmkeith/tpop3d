/*
 * mailspool.c:
 * Berkeley mailspool handling.
 *
 * Note that this makes _no_ attempt to handle the awful SysVism of not
 * quoting /^From / in body text and attempting to use Content-Length to
 * figure out where messages start and end.
 *
 * See
 * http://home.netscape.com/eng/mozilla/2.0/relnotes/demo/content-length.html
 *
 * This also, optionally, allows the metadata stored into mailspools (why,
 * Washington University, why?) by PINE to be ignored. This means that those
 * who use PINE locally and a POP3 client remotely will not find themselves
 * continually downloading copies of "DON'T DELETE THIS MESSAGE -- ...".
 *
 * A further option allows caches of message offsets in a mailspool to be
 * made, reducing the time needed to open a mailspool.
 *
 * Copyright (c) 2001 Chris Lightfoot. All rights reserved.
 *
 */

#ifdef HAVE_CONFIG_H
#include "configuration.h"
#endif /* HAVE_CONFIG_H */

#ifdef MBOX_BSD
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
#include "mailbox.h"
#include "md5.h"
#include "stringmap.h"
#include "util.h"

#ifdef MBOX_BSD_SAVE_INDICES
/* Stuff to support a metadata cache. */
int mailspool_save_indices;

char *mailspool_find_index(mailbox m);
int mailspool_save_index(mailbox m);
int mailspool_load_index(mailbox m);
#endif /* MBOX_BSD_SAVE_INDICES */

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

/* mailspool_make_indexpoint:
 * Make an indexpoint.
 */
void mailspool_make_indexpoint(struct indexpoint *x, const size_t offset, const size_t length, const size_t msglength, const unsigned char *hash) {
    memset(x, 0, sizeof(struct indexpoint));

    x->offset = offset;
    x->length = length;
    x->msglength = msglength;
    if (hash) memcpy(x->hash, hash, 16);
}

/* mailspool_new_from_file:
 * Open a file, lock it, and form an index of the messages in it.
 */
mailbox mailspool_new_from_file(const char *filename) {
    mailbox M, failM = NULL;
    int i;
    struct timeval tv1, tv2;
    float f;
    
    M = xcalloc(1, sizeof *M);
    if (!M) return NULL;

    M->delete = mailspool_delete;
    M->apply_changes = mailspool_apply_changes;
    M->send_message = mailspool_send_message;

    /* Allocate space for the index. */
    M->index = (struct indexpoint*)xcalloc(32, sizeof(struct indexpoint));
    M->size = 32;
    
    if (stat(filename, &(M->st)) == -1) {
        /* If the mailspool doesn't exist, fail silently, since this may be
         * getting called from find_mailbox.
         */
        if (errno == ENOENT) failM = MBOX_NOENT;
        else log_print(LOG_INFO, "mailspool_new_from_file: stat(%s): %m", filename);
        goto fail;
    } else M->name = strdup(filename);
    
    /* Naive locking strategy. */
    for (i = 0; i < MAILSPOOL_LOCK_TRIES; ++i) {
        M->fd = open(M->name, O_RDWR);
        if (M->fd == -1) {
            log_print(LOG_ERR, "mailspool_new_from_file: %m");
            goto fail;
        }
     
        if (file_lock(M->fd, M->name)) break;

        close(M->fd);
        M->fd = -1;

        sleep(MAILSPOOL_LOCK_WAIT);
    }

    if (M->fd == -1) {
        log_print(LOG_ERR, _("mailspool_new_from_file: failed to lock %s: %m"), filename);
        goto fail;
    }

    gettimeofday(&tv1, NULL);
    
    /* Build index of mailspool. */
#ifdef MBOX_BSD_SAVE_INDICES
    if (mailspool_save_indices) {
        if (mailspool_load_index(M) == -1) {
            log_print(LOG_ERR, _("mailspool_new_from_file: unable to index mailspool"));
            goto fail;
        }
    } else
#endif
    if (mailspool_build_index(M, NULL) == -1) {
        log_print(LOG_ERR, _("mailspool_new_from_file: unable to index mailspool"));
        goto fail;
    }

    gettimeofday(&tv2, NULL);
    f = (float)(tv2.tv_sec - tv1.tv_sec) + 1e-6 * (float)(tv2.tv_usec - tv1.tv_usec);
    log_print(LOG_DEBUG, _("mailspool_new_from_file: indexed mailspool %s (%d bytes) in %0.3fs"), filename, (int)M->st.st_size, f);
    
    return M;

fail:
    if (M) mailspool_delete(M);
    return failM;
}

/* mailspool_delete:
 * Deletion specific to mailspools.
 */
void mailspool_delete(mailbox m) {
    if (!m) return;
    if (m->name) file_unlock(m->fd, m->name);
    if (m->fd != -1) close(m->fd);
    
    mailbox_delete(m);
}

/* memstr:
 * Locate needle, of length n_len, in haystack, of length h_len, returning
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

/*
struct timeval TT;
#define ts(a)  do { struct timeval tv; float t; gettimeofday(&tv, NULL); t = (double)(tv.tv_sec - TT.tv_sec) + 1e-6 * (double)(tv.tv_usec - TT.tv_usec); log_print(LOG_DEBUG, a " delta = %lf", t); TT = tv; } while (0)
*/

/* mailspool_build_index:
 * Build an index of a mailspool. Uses mmap(2) for speed. Assumes that
 * mailspools use only '\n' to indicate EOL. Returns 0 on success or -1 on
 * failure.
 */
int mailspool_build_index(mailbox M, char *filemem) {
    char *p, *q;
    size_t len, len2;
    int first = 0;

    if (!M || M->fd == -1) return -1;

    len = len2 = M->st.st_size;

    if (len < 16) return 0; /* Mailspool doesn't contain any messages. */

    len += PAGESIZE - (len % PAGESIZE);
    if (!filemem) {
        filemem = mmap(0, len, PROT_READ, MAP_PRIVATE, M->fd, 0);
        if (filemem == MAP_FAILED) {
            log_print(LOG_ERR, "mailspool_build_index(%s): mmap: %m", M->name);
            return -1;
        }
    }

    if (M->num > 0) {
        /* Perhaps we are parsing the tail of the file, after reading a
         * partial index?
         */
        struct indexpoint *P = M->index + M->num - 1;
        p = filemem + P->offset + P->msglength - 2;
        first = M->num;
        log_print(LOG_DEBUG, _("mailspool_build_index(%s): first %d messages indexed from cached metadata"), M->name, first);
    } else
        /* Nope, never seen this one before. */
        p = filemem - 2;


    
    /* Extract all From lines from file */
    do {
        p += 2;
        q = (char*)memchr(p, '\n', len - (p - filemem));

        if (q) {
            size_t o, l;
            struct indexpoint pt;
            o = p - filemem;
            l = q - p;

            mailspool_make_indexpoint(&pt, o, l, 0, NULL);
            mailbox_add_indexpoint(M, &pt);

            p = memstr(q, len2 - (q - filemem), "\n\nFrom ", 7);
        } else break;
    } while (p && p < filemem + len2);

    if (first < M->num) {
        struct indexpoint *t;
        /* OK, we're done, figure out the lengths */
        for (t = M->index; t < M->index + M->num - 1; ++t)
            t->msglength = (t + 1)->offset - t->offset;
        t->msglength = M->st.st_size - t->offset;

        /* We generate "unique" IDs by hashing the first 512 or so bytes of the
         * data in each message. Only do this for messages we've just found.
         */
        for (t = M->index; t < M->index + M->num; ++t) {
            MD5_CTX ctx;
            size_t n = 512;

            if (n > t->msglength) n = t->msglength;
            
            /* Compute MD5 */
            MD5Init(&ctx);
            MD5Update(&ctx, (unsigned char*)filemem + t->offset, n);
            MD5Final(t->hash, &ctx);
        }
    }

#ifdef IGNORE_CCLIENT_METADATA
    /* Optionally, check whether the first message in the mailspool is
     * internal data used by c-client; such messages contain the following
     * headers:
     *
     *  Subject: DON'T DELETE THIS MESSAGE -- FOLDER INTERNAL DATA
     *  X-IMAP: <some numbers>
     *
     * The metadata message is assumed to be the first one in the mailspool.
     */
    if (M->num >= 1) {
        struct indexpoint *P = M->index;
        p = memstr(filemem + P->offset, P->msglength, "\n\n", 2);
        if (p) {
            const char hdr1[] = "\nX-IMAP: ", hdr2[] = "Subject: DON'T DELETE THIS MESSAGE -- FOLDER INTERNAL DATA\n";
            if (memstr(filemem + P->offset, p - filemem, hdr1, strlen(hdr1)) && memstr(filemem + P->offset, p - filemem, hdr2, strlen(hdr2))) {
                log_print(LOG_DEBUG, "mailspool_build_index(%s): skipping c-client metadata", M->name);
                memmove((void*)M->index, (void*)(M->index + 1), sizeof(struct indexpoint) * (M->num - 1));
                --M->num;
            }
        }
    }
#endif /* IGNORE_CCLIENT_METADATA */

    munmap(filemem, len);
/* ts("munmap");     */
    return 0;
}

/* mailspool_send_message:
 * Front-end to write_file in util.c.
 */
int mailspool_send_message(const mailbox M, int sck, const int i, int n) {
    struct indexpoint *x;

    if (!M) return 0;
    if (i < 0 || i >= M->num) return 0;
    x = M->index + i;
    return write_file(M->fd, sck, x->offset, x->length + 1, x->msglength, n);
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
int mailspool_apply_changes(mailbox M) {
    char *filemem, *s, *d;
    size_t len;
    struct indexpoint *I, *J, *K, *End;

    if (!M || M->fd == -1) return 1;

    if (M->numdeleted == 0)
        /* No messages deleted, do nothing. */
        return 1;
    else if (M->numdeleted == M->num) {
        /* All messages deleted, so just truncate file at the beginning of the
         * first message.
         */
        if (ftruncate(M->fd, M->index->offset) == -1) {
            log_print(LOG_ERR, "mailspool_apply_changes(%s): ftruncate: %m", M->name);
            return 0;
        } else return 1;
    }

    /* We need to do something more complicated, so map the mailspool. */
    len = M->st.st_size;
    len += PAGESIZE - (len % PAGESIZE);
    filemem = mmap(0, len, PROT_WRITE | PROT_READ, MAP_SHARED, M->fd, 0);
    if (filemem == MAP_FAILED) {
        log_print(LOG_ERR, "mailspool_apply_changes(%s): mmap: %m", M->name);
        close(M->fd);
        return 0;
    }

    I = M->index;
    End = M->index + M->num;
    d = filemem;

    /* Find the first message to be deleted. */
    while (I < End && !I->deleted) ++I;
    if (I == End) {
        if (munmap(filemem, len) == -1) log_print(LOG_ERR, "mailspool_send_message: munmap: %m");
        log_print(LOG_ERR, _("mailspool_apply_changes(%s): inconsistency in mailspool data"), M->name);
        return 0;
    }
    d = filemem + I->offset;
    
    do {
        /* Find the first non-deleted message after this block. */
        J = I;
        while (J < End && J->deleted) ++J;
        if (J == End) break;
        else {
            /* Find the end of this chunk. */
            size_t copylen = 0;
            s = filemem + J->offset;
            K = J;
            while (K < End && !K->deleted) copylen += (K++)->msglength;

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
        log_print(LOG_ERR, "mailspool_apply_changes(%s): ftruncate: %m", M->name);
        if (munmap(filemem, len) == -1) log_print(LOG_ERR, "mailspool_send_message: munmap: %m");
        return 0;
    }
    
    /* Done, unmap the file. */
    if (munmap(filemem, len) == -1) {
        log_print(LOG_ERR, "mailspool_send_message: munmap: %m");
        return 0;
    }

#ifdef MBOX_BSD_SAVE_INDICES
    if (mailspool_save_indices && !mailspool_save_index(M))
        log_print(LOG_WARNING, _("mailspool_apply_changes(%s): unable to save mailspool index"), M->name);
#endif /* MBOX_BSD_SAVE_INDICES */
    
    return 1;
}

#ifdef MBOX_BSD_SAVE_INDICES

/* Optionally, tpop3d can save indices of the offsets of messages within BSD
 * mailspools. Obviously this is a win speed-wise, but it is a bit messy.
 *
 * The game is that we save (in a textual format, giving the nod to
 * machine-independence for lunatics who believe in NFS-mounted mailspools)
 * the offset, `From ' line length, message size and derived unique ID (MD5
 * hash of beginning of message) for each message.
 *
 * The load routine can then check that the message offsets point to plausible
 * messages (begin `From ' and have the right MD5 hash).
 *
 * We write out the index if we have parsed a mailspool without the benefit of
 * an index; or after a mailspool is modified.
 *
 * Note that we don't rely on modification times for this, on the basis that
 * some dumb pieces of software (I love you, PINE!) will modify them for some
 * deranged reason probably known only to people who live up in that corner of
 * the world among the giant redwoods, collapsing suspension bridges, and
 * 1970s software empires.
 */

/* mailspool_find_index:
 * Find the name of a mailspool's index file, using the spec in the config
 * file.
 */
extern stringmap config;

char *mailspool_find_index(mailbox m) {
    char *path, *file, *escaped_name;
    char *p, *q;
    item *I;
    char *subspec, *indexname;
    struct sverr err;

    I = stringmap_find(config, "mailspool-index");
    if (!I) return NULL;
    
    subspec = (char*)I->v;

    /* First find out what name the index should have. We supply the user with
     * the path, filename, and an escaped form of the full name; so,
     *
     *  /var/spool/mail/fred -> name = /var/spool/mail/fred
     *                          path = /var/spool/mail
     *                          file = fred
     *                          escaped_name = %2fvar%2fspool%2fmail%2ffred
     *
     * This allows you to say, for instance,
     *  mailspool-index:    /var/spool/tpop3d/$(escaped_name)
     * or
     *  mailspool-index:    $(path)/.$(file).tpop3d-index
     *
     * In either case, the path in which the index is saved needs to have
     * permissions which allow the user who owns the mailspool to write a new
     * file to it. 1777 would be traditional.
     *
     */
    path = strdup(m->name);
    p = strrchr(path, '/');
    if (p) *p = 0;
    file = strdup(p + 1);
    escaped_name = xcalloc(strlen(m->name) * 3 + 2, 1);

    /* Form HTTP-style escaped version of name. Only escape % and /, though. */
    for (p = m->name, q = escaped_name; *p; ++p) {
        if (strchr("/%", *p))
            q += sprintf(q, "%%%02x", (int)*p);
        else
            *(q++) = *p;
    }

    indexname = substitute_variables(subspec, &err, 4, "name", m->name, "path", path, "file", file, "escaped_name", escaped_name);
    if (!indexname) {
        log_print(LOG_ERR, _("mailspool_find_index: %s near `%.16s'"), err.msg, subspec + err.offset);
        goto fail;
    }

fail:
    if (path) xfree(path);
    if (file) xfree(file);
    if (escaped_name) xfree(escaped_name);

    return indexname;
}

/* This is a signature we put at the top of our files to identify them later. */
char index_signature[] =
"# This is a mailspool index file, generated by tpop3d, version " TPOP3D_VERSION ".\n"
"# Its purpose is to speed up the parsing of mailspool files by the POP3\n"
"# server. If you delete this file, it will be automatically recreated by\n"
"# tpop3d. So don't do that.\n";

/* mailbox_save_index:
 * Save an index of a mailspool. Returns 1 on success or 0 on failure. Uses
 * stdio, which is unfortunate but makes it a bit easier to write. The
 * mailspool must be locked when this is called. Makes some attempt to avoid
 * clobbering files via symlink attacks.
 */
int mailspool_save_index(mailbox m) {
    char *indexfile;
    int ret = 0;
    int fd = -1;
    FILE *fp = NULL;
    int offset;
    struct indexpoint *I, *End;
    int a;
    char buf[1024];

    if (!m || m->fd == -1) return 1;

    indexfile = mailspool_find_index(m);
    if (!indexfile) return -1;

    /* OK, now we need to save the thing. */
    fd = open(indexfile, O_RDWR | O_CREAT, 0600); /* Ensure correct permissions. */
    if (fd == -1) {
        log_print(LOG_ERR, "mailspool_save_index(%s): %m", indexfile);
        goto fail;
    }

    /* Now we need to make sure that there isn't some sort of childish symlink
     * attack in progress.
     */
    a = readlink(indexfile, buf, sizeof(buf));
    if (a == 0) {
        log_print(LOG_ERR, _("mailspool_save_index(%s): possible security problem: index file exists and is a symlink to `%s'"), indexfile, buf);
        goto fail;
    } else if (a == -1 && errno != EINVAL) {
        log_print(LOG_ERR, _("mailspool_save_index(%s): possible security problem: index file exists, and is a symlink, but readlink failed: %m"), indexfile);
        goto fail;
    }

    /* We're OK. Clobber the file and start writing to it. */
    ftruncate(fd, 0);
    
    fp = fdopen(fd, "wt");
    if (!fp) {
        log_print(LOG_ERR, "mailspool_save_index(%s): %m", indexfile);
        goto fail;
    }

    /* Write a header to the file. */
    fprintf(fp, "%s", index_signature);
    
    /* Now we need to save data about all the messages in the mailspool. But
     * note that some of them might have been deleted, so we rely on the
     * message sizes rather than their offsets. */
    if (m->numdeleted < m->num) {
        /* There are some remaining messages. */
        I = m->index;
        End = m->index + m->num;
        offset = I->offset;    /* get first message offset to deal with cclient metadata etc. */

        while (I < End) {
            if (!I->deleted) {
                fprintf(fp, "%08x %08x %08x %s\n", (unsigned int)offset, (unsigned int)I->length, (unsigned int)I->msglength, hex_digest(I->hash)); /* XXX error return? */
                offset += I->msglength;
            }
            ++I;
        }
    }

    ret = 1;

fail:
    if (indexfile) xfree(indexfile);
    if (fp) fclose(fp);
    else if (fd != -1) close(fd);
    
    return ret;
}

/* mailspool_load_index:
 * Attempts to construct a mailspool index from a saved index file, if one
 * exists and is of the correct format. We may find that we need to re-parse
 * the tail of the file; this is done by calling into the `normal'
 * mailspool_build_index. Returns 0 on success or -1 on failure.
 */
int mailspool_load_index(mailbox m) {
    char *indexfile;
    FILE *fp = NULL;
    struct stat st;
    int offset, length, msglength;
    char hexdigest[33] = {0};
    char sigbuf[sizeof(index_signature)];
    char *filemem = NULL;
    size_t len, len2;
    int num, r;

    if (!m || m->fd == -1) goto fail;

    indexfile = mailspool_find_index(m);
    if (!indexfile) goto fail;

    fp = fopen(indexfile, "rt");
    if (!fp) {
        log_print(LOG_WARNING, "mailspool_load_index(%s): %m", indexfile);
        goto fail;
    }

    /* Security. The file must have the correct permissions, and be owned by
     * ourselves.
     */
    if (fstat(fileno(fp), &st) == -1) {
        log_print(LOG_ERR, "mailspool_load_index(%s): %m", indexfile);
        goto fail;
    } else if ((st.st_mode & 0777) != 0600 || m->st.st_uid != getuid()) {
        log_print(LOG_ERR, _("mailspool_load_index(%s): possible security problem: index exists, but it has the wrong owner or file permissions"), indexfile);
        log_print(LOG_ERR, _("mailspool_load_index(%s): owner is %d, should be %d; mode 0%o, should be 0600"), indexfile,
                            m->st.st_uid, getuid(), m->st.st_mode & 0777);
        goto fail;
    }

    /* OK, found an index file; let's try loading some data out of it. */
    if (fread(sigbuf, 1, sizeof(sigbuf) - 1, fp) != sizeof(sigbuf) - 1 || memcmp(sigbuf, index_signature, sizeof(sigbuf) - 1) != 0) {
        log_print(LOG_WARNING, _("mailspool_load_index(%s): index exists, but is of wrong format; ignoring"), indexfile);
        goto fail;
    }

    /* Should now get a bunch of offset/hash lines. Stuff these into the
     * mailbox object. Also mmap the real mailspool so we can check these.
     */
    len = len2 = m->st.st_size;

    if (len < 16) goto fail;

    len += PAGESIZE - (len % PAGESIZE);
    filemem = mmap(0, len, PROT_READ, MAP_PRIVATE, m->fd, 0);
    if (filemem == MAP_FAILED) {
        log_print(LOG_ERR, "mailspool_load_index(%s): mmap: %m", m->name);
        goto fail;
    }

    while (fscanf(fp, "%8x %8x %8x %32[0-9a-f]", &offset, &length, &msglength, hexdigest) == 4) {
        struct indexpoint x;
        MD5_CTX ctx;
        size_t n = 512;
        unsigned char realhash[16];

        /* XXX check validity here. */
        mailspool_make_indexpoint(&x, offset, length, msglength, NULL);
        unhex_digest(hexdigest, x.hash);

        if (x.offset + x.msglength > m->st.st_size || memcmp(filemem + x.offset, "From ", 5) != 0)
            break;

        if (n > x.msglength) n = x.msglength;

        /* Compute MD5 */
        MD5Init(&ctx);
        MD5Update(&ctx, (unsigned char*)filemem + x.offset, n);
        MD5Final(realhash, &ctx);

        if (memcmp(realhash, x.hash, 16) != 0)
            break;

        /* OK, this message seems to have been indexed correctly.... */
        mailbox_add_indexpoint(m, &x);
    }

    if (!feof(fp)) {
        log_print(LOG_WARNING, _("mailspool_load_index(%s): index exists, but has some stale or corrupt data"), indexfile);
        goto fail;
    }

    r = 0;

    /* That's it. Messages after this one (if any) must be indexed `properly'. */

fail:
    if (fp) fclose(fp);

    if (indexfile) xfree(indexfile);

    /* Whatever happens, have a go at indexing the rest of the file. */
    num = m->num;
    r = mailspool_build_index(m, filemem);
    if (m->num > num) mailspool_save_index(m);
    return r;
}

#endif /* MBOX_BSD_SAVE_INDICES */

#endif /* MBOX_BSD */
