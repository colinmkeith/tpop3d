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
#include "mailbox.h"
#include "stringmap.h"
#include "tokenise.h"
#include "util.h"

/* mbox_drivers:
 * References various mailbox drivers, New ones should be added as below. Note
 * that the first driver in this list will be used if mailbox_new is called
 * with a NULL mailspool type, so it should be a sensible default.
 */
struct mboxdrv mbox_drivers[] = {
#ifdef MBOX_BSD
    /* Traditional, "From " separated mail spool. */
    {"bsd",
     "BSD (`Unix') mailspool",
     mailspool_new_from_file},
#endif /* MBOX_BSD */

#ifdef MBOX_MAILDIR
    /* The maildir format of qmail. */
    {"maildir",
     "Qmail-style maildir",
     maildir_new},
#endif /* WITH_MAILDIR */

    /* A null mailspool implementation. Must be the last driver listed. */
    {"empty",
     "Empty mailbox",
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
    
    print_log(LOG_ERR, "mailbox_new(%s): request for unknown mailbox type %s", filename, type);
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
    if (m->index) vector_delete_free(m->index);
    if (m->name) free(m->name);
    free(m);
}

/* emptymbox_new:
 * New empty mailbox.
 */
mailbox emptymbox_new(const char *unused) {
    mailbox M;
    M = (mailbox)malloc(sizeof(struct _mailbox));
    if (!M) return NULL;
    memset(M, 0, sizeof(struct _mailbox));

    M->delete = mailbox_delete;                 /* generic destructor */
    M->apply_changes = emptymbox_apply_changes;
    M->send_message = NULL;                     /* should never be called */

    M->name = strdup("[empty mailbox]");
    M->index = vector_new();

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
    
    for (i = 0; i < t->toks->n_used; ++i) {
        char *str = t->toks->ary[i].v, *mdrv = NULL, *subspec, *path;
        struct sverr err;

        subspec = strchr(str, ':');
        if (subspec) {
            mdrv = str;
            *subspec++ = 0;
        } else subspec = str;

        path = substitute_variables(subspec, &err, 3, "user", user, "domain", domain, "home", home);
        if (!path)
            /* Some sort of syntax error. */
            print_log(LOG_ERR, _("try_mailbox_locations: %s near `%.16s'"), err.msg, subspec + err.offset);
        else {
            m = mailbox_new(path, mdrv);
            free(path);
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
 * couldn't be opened because of an error. This is to prevent the situation
 * where, say, bsd:/var/spool/mail/$(user) and maildir:$(home)/Maildir are
 * allowed mailbox names, both exist, and the former is locked. It is
 * important the the view of the mailbox presented to the user is consistent,
 * so a failure to lock a given mailspool must not cause the program to go off
 * and use a different one.
 */
extern stringmap config;

mailbox find_mailbox(authcontext a) {
    mailbox m = MBOX_NOENT;
    char *buffer;
    item *I;
 
    /* Try the driver-specific config option. */
    buffer = (char*)malloc(strlen("auth--mailbox") + strlen(a->auth) + 1);
    sprintf(buffer, "auth-%s-mailbox", a->auth);
    if ((I = stringmap_find(config, buffer)))
        m = try_mailbox_locations(I->v, a->user, a->domain, a->home);
    free(buffer);

    /* Then the global one. */
    if (m == MBOX_NOENT && (I = stringmap_find(config, "mailbox")))
        m = try_mailbox_locations(I->v, a->user, a->domain, a->home);
    
#ifdef MAILSPOOL_DIR
    /* Then the compiled-in default. */
    if (m == MBOX_NOENT) {
        buffer = (char*)malloc(strlen(MAILSPOOL_DIR) + 1 + strlen(a->user) + 1);
        sprintf(buffer, MAILSPOOL_DIR "/%s", a->user);
        m = mailbox_new(buffer, NULL);
        free(buffer);
    }
#endif

    /* No good. Give the user an empty mailbox. */
    if (m == MBOX_NOENT) {
        m = emptymbox_new(NULL);
        print_log(LOG_WARNING, "find_mailbox: using empty mailbox for user %s", a->user);
    }
    
    return m;
}


