/*
 * mailbox.c:
 * Generic mailbox support for tpop3d.
 *
 * Copyright (c) 2001 Chris Lightfoot, Paul Makepeace. All rights reserved.
 *
 * $Id$
 *
 */

#ifdef HAVE_CONFIG_H
#include "configuration.h"
#endif /* HAVE_CONFIG_H */

#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "authswitch.h"
#include "config.h"
#include "mailbox.h"
#include "tokenise.h"
#include "util.h"

/* mbox_drivers:
 * References various mailbox drivers, New ones should be added as below. Note
 * that the first driver in this list will be used if mailbox_new is called
 * with a NULL mailspool type, so it should be a sensible default. */
#define _X(String) (String)

struct mboxdrv mbox_drivers[] = {
#ifdef MBOX_BSD
    /* Traditional, `From ' separated mail spool. */
    {"bsd",
#ifdef MBOX_BSD_SAVE_INDICES
     _X("BSD (`Unix') mailspool, with index saving support"),
#else
     _X("BSD (`Unix') mailspool"),
#endif
     mailspool_new_from_file},
#endif /* MBOX_BSD */

#ifdef MBOX_MAILDIR
    /* The maildir format of qmail. */
    {"maildir",
     _X("Qmail-style maildir"),
     maildir_new},
#endif /* WITH_MAILDIR */

    /* A null mailspool implementation. Must be the last driver listed. */
    {"empty",
     _X("Empty mailbox"),
     emptymbox_new}
};

#define NUM_MBOX_DRIVERS    (sizeof(mbox_drivers) / sizeof(struct mboxdrv))
#define mbox_drivers_end    mbox_drivers + NUM_MBOX_DRIVERS

/* mailbox_describe:
 * Describe available mailbox drivers.
 */
void mailbox_describe(FILE *fp) {
    const struct mboxdrv *mr;
    fprintf(fp, _("Available mailbox drivers:\n\n"));
    for (mr = mbox_drivers; mr < mbox_drivers_end; ++mr) {
        fprintf(fp, "  %-16s %s\n", mr->name, _(mr->description));
    }
    fprintf(fp, "\n");
}

/* mailbox_new:
 * Create a new mailspool of the specified type, or a default type if the
 * passed value is NULL.
 */
mailbox mailbox_new(const char *filename, const char *type) {
    struct mboxdrv *mr;

    if (!type) return mbox_drivers[0].m_new(filename);

    for (mr = mbox_drivers; mr < mbox_drivers_end; ++mr)
        if (strcmp(type, mr->name) == 0) return mr->m_new(filename);
    
    log_print(LOG_ERR, _("mailbox_new(%s): request for unknown mailbox type %s"), filename, type);
    return MBOX_NOENT;
}

/* mailbox_delete:
 * Delete a mailbox object (but don't actually delete messages in the
 * mailspool... the terminology is from C++ so it doesn't have to be logical).
 *
 * Note that this does `generic' deletion; there should be specific
 * destructors for each type of mailbox.
 */
void mailbox_delete(mailbox m) {
    if (!m) return;
    if (m->index) {
        struct indexpoint *i;
        for (i = m->index; i < m->index + m->num; ++i)
            if (i->filename) xfree(i->filename);     /* should this be in a maildir-specific destructor? */
        xfree(m->index);
    }
    if (m->name) xfree(m->name);
    xfree(m);
}

/* mailbox_add_indexpoint:
 * Add an indexpoint to a mailbox.
 */
void mailbox_add_indexpoint(mailbox m, const struct indexpoint *i) {
    if (m->num == m->size) {
        m->index = xrealloc(m->index, m->size * sizeof(struct indexpoint) * 2);
        m->size *= 2;
    }
    m->index[m->num++] = *i;
}

/* emptymbox_new:
 * New empty mailbox.
 */
mailbox emptymbox_new(const char *unused) {
    mailbox M;
    M = xcalloc(1, sizeof *M);
    if (!M) return NULL;

    M->delete = mailbox_delete;                 /* generic destructor */
    M->apply_changes = emptymbox_apply_changes;
    M->send_message = NULL;                     /* should never be called */

    M->name = strdup(_("[empty mailbox]"));
    M->index = NULL;

    return M;
}

/* emptymbox_apply_changes:
 * Null function for empty mailbox.
 */
int emptymbox_apply_changes(mailbox M) {
    return 1;
}

/* try_mailbox_locations:
 * Helper function for find_mailbox.
 */
mailbox try_mailbox_locations(const char *specs, const char *user, const char *domain, const char *home) {
    tokens t = tokens_new(specs, " \t");
    mailbox m = NULL;
    int i;

    if (!t) return NULL;
    
    for (i = 0; i < t->num; ++i) {
        char *str = t->toks[i], *mdrv = NULL, *subspec, *path;
        struct sverr err;

        subspec = strchr(str, ':');
        if (subspec) {
            mdrv = str;
            *subspec++ = 0;
        } else subspec = str;

        path = substitute_variables(subspec, &err, 3, "user", user, "domain", domain, "home", home);
        if (!path)
            /* Some sort of syntax error. */
            log_print(LOG_ERR, _("try_mailbox_locations: %s near `%.16s'"), err.msg, subspec + err.offset);
        else {
            m = mailbox_new(path, mdrv);
            xfree(path);
            if (!m || m != MBOX_NOENT) break; /* Return in case of error or if we found the mailspool. */
        }
    }
    
    tokens_delete(t);
    return m;
}

/* find_mailbox:
 * Try to find a user's mailbox. This first tries the locations in the
 * $(authdrv)-mailbox: config option, or, failing that, the global mailbox:
 * config option, or, failing that, MAILSPOOL_DIR/$(user).
 *
 * The config options may contain a number of options of the form
 * $(mboxdrv):<substitution string>, or <substitution string>; in the latter
 * case, then a default mailbox driver is assumed.
 *
 * This distinguishes between nonexistent mailboxes and mailboxes which
 * couldn't be opened because of an error. This is to prevent SNAFUs where,
 * say, bsd:/var/spool/mail/$(user) and maildir:$(home)/Maildir are allowed
 * mailbox names, both exist, and the former is locked. It is important that
 * the view of the mailbox presented to the user is consistent, so a failure
 * to lock a given mailspool must not cause the program to go off and use a
 * different one. */
mailbox find_mailbox(authcontext a) {
    mailbox m = MBOX_NOENT;
    char *buffer;
    char *s;
 
    /* Try the driver-specific config option. */
    buffer = xmalloc(strlen("auth--mailbox") + strlen(a->auth) + 1);
    sprintf(buffer, "auth-%s-mailbox", a->auth);
    if ((s = config_get_string(buffer)))
        m = try_mailbox_locations(s, a->user, a->domain, a->home);
    xfree(buffer);

    /* Then the global one. */
    if (m == MBOX_NOENT && (s = config_get_string("mailbox")))
        m = try_mailbox_locations(s, a->user, a->domain, a->home);
    
#ifdef MAILSPOOL_DIR
    /* Then the compiled-in default. */
    if (m == MBOX_NOENT) {
        buffer = xmalloc(strlen(MAILSPOOL_DIR) + 1 + strlen(a->user) + 1);
        sprintf(buffer, MAILSPOOL_DIR "/%s", a->user);
        m = mailbox_new(buffer, NULL);
        xfree(buffer);
    }
#endif

    /* No good. Give the user an empty mailbox. */
    if (m == MBOX_NOENT) {
        m = emptymbox_new(NULL);
        log_print(LOG_WARNING, _("find_mailbox: using empty mailbox for user %s"), a->user);
    }
    
    return m;
}


