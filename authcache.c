/*
 * authcache.c:
 * Cache authentication data.
 *
 * Copyright (c) 2003 Chris Lightfoot. All rights reserved.
 * Email: chris@ex-parrot.com; WWW: http://www.ex-parrot.com/~chris/
 *
 */

static const char rcsid[] = "$Id$";

#include <sys/types.h>

#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#include "authswitch.h"
#include "config.h"
#include "md5.h"
#include "util.h"

/* 
 * Obviously we can only cache USER+PASS authentication attempts, since the 
 * APOP method uses a random challenge for each authentication. This is fine,
 * since most sites don't use APOP anyway.
 *
 * The strategy is to use an MD5 checksum of the parameters passed to the
 * authentication driver as a key in a hash table. We return a copy of any
 * cached authentication information, unless it's older than a certain
 * threshold, in which case it's discarded. We don't cache negative
 * authentication results.
 */

/* Is the cache enabled? */
static int use_cache;

/* Optionally, the authentication cache can use the client host as part of the
 * hash table host. Typically this is undesirable, since then the cache will
 * only work for connections from a single IP address. */
static int key_by_client_host;

/* How long an entry persists in the cache. */
static int entry_lifetime;

/* authcontext_copy CONTEXT
 * Return a copy of the passed authentication CONTEXT. */
static authcontext authcontext_copy(const authcontext A) {
    authcontext B;
    alloc_struct(_authcontext, B);

    B->uid = A->uid;
    B->gid = A->gid;
#define COPYS(x)        B->x = A->x ? xstrdup(A->x) : NULL
    COPYS(mboxdrv);
    COPYS(mailbox);
    COPYS(auth);
    COPYS(user);
    COPYS(home);
    COPYS(local_part);
    COPYS(domain);
#undef COPYS

    return B;
}

static struct {
    size_t nbits;
    size_t nfilled;
    struct cacheentry {
        time_t when;
        unsigned char hash[16];
        authcontext A;          /* NULL == slot empty */
    } *slots;
} authcache;

#define CACHESLOTS      (1 << authcache.nbits)

/* hashval MD5 NUM
 * Return a hash formed from the first NUM bytes of the MD5 hash. */
static unsigned long hashval(const unsigned char hash[16], const size_t nbits) {
    unsigned long u;
    size_t i;
    for (i = 0, u = 0; i < 4; ++i)
        u |= ((unsigned long)hash[i]) << (i * 8);
    return u & ((1 << nbits) - 1);
}

/* resize_cache NUM
 * Resize the hash table so that it uses the first NUM bytes of the argument
 * digest as a hash key. */
static void resize_cache(const size_t nbits) {
    struct cacheentry *newslots;
    size_t N, i;
    N = 1 << nbits;
    newslots = xmalloc(N * sizeof *newslots);
    for (i = 0; i < N; ++i)
        newslots[i].A = NULL;

    if (authcache.slots) {
        /* Copy old cache entries into new. */
        for (i = 0; i < CACHESLOTS; ++i) {
            if (authcache.slots[i].A) {
                unsigned long u;
                u = hashval(authcache.slots[i].hash, nbits);
                while (newslots[u].A)
                    u = (u + 1) % N;
                newslots[u] = authcache.slots[i];
            }
        }
        
        xfree(authcache.slots);
    }

    authcache.slots = newslots;
    authcache.nbits = nbits;
}

/* authcache_init
 * Initialise the authentication cache. */
void authcache_init(void) {
    if ((use_cache = config_get_bool("authcache-enable"))) {
        key_by_client_host = config_get_bool("authcache-use-client-host");
        if (!config_get_int("authcache-entry-lifetime", &entry_lifetime) || entry_lifetime <= 0)
            /* To be useful, most authentications must go through the cache.
             * Because we can assume that passwords are changed infrequently
             * by comparison with POP sessions, we should just make this much
             * longer than the interval between sessions. As a default, assume
             * one hour. */
            entry_lifetime = 3600;
        resize_cache(8);
    }
}

/* authcache_close
 * Close down the authentication cache. */
void authcache_close(void) {
    size_t i;
    if (!use_cache)
        return;
    if (authcache.slots) {
        for (i = 0; i < CACHESLOTS; ++i)
            if (authcache.slots[i].A)
                authcontext_delete(authcache.slots[i].A);
        xfree(authcache.slots);
        authcache.slots = NULL;
    }
}

/* make_arg_hash HASH USER LOCALPART DOMAIN PASSWORD CLIENTHOST SERVERHOST
 * Generate an MD5 checksum of the arguments, to use as a hash key. */
static void make_arg_hash(unsigned char hash[16], const char *user, const char *local_part, const char *domain, const char *pass, const char *clienthost, const char *serverhost) {
    md5_ctx c;
    MD5Init(&c);
#define ADDTOHASH(a)        if ((a)) MD5Update(&c, (unsigned char*)(a), strlen((a)) + 1)
    ADDTOHASH(user);
    ADDTOHASH(local_part);
    ADDTOHASH(domain);
    ADDTOHASH(pass);
    if (key_by_client_host)
        ADDTOHASH(clienthost);
    ADDTOHASH(serverhost);
#undef ADDTOHASH
    MD5Final(hash, &c);
}

/* remove_cache_entry INDEX
 * Remove the cache entry with the given INDEX. */
static void remove_cache_entry(unsigned long u0) {
    unsigned long u, uprev;
    authcontext_delete(authcache.slots[u0].A);
    authcache.slots[u0].A = NULL;
    /* Need to close up any other entries in the table. */
    for (uprev = u, u = (u0 + 1) % CACHESLOTS; hashval(authcache.slots[u].hash, authcache.nbits) == u0; uprev = u, u = (u + 1) % CACHESLOTS) {
        authcache.slots[uprev] = authcache.slots[u];
        authcache.slots[u].A = NULL;
    }
    --authcache.nfilled;
}

/* authcache_new_user_pass USER LOCALPART DOMAIN PASSWORD CLIENTHOST SERVERHOST
 * Return any cached authentication context for the given arguments. */
authcontext authcache_new_user_pass(const char *user, const char *local_part, const char *domain, const char *pass, const char *clienthost, const char *serverhost) {
    unsigned char hash[16];
    unsigned long u, u0;
    if (!use_cache)
        return NULL;
    make_arg_hash(hash, user, local_part, domain, pass, clienthost, serverhost);
    u = u0 = hashval(hash, authcache.nbits);
    do {
        if (!authcache.slots[u].A)
            break;
        else if (0 == memcmp(authcache.slots[u].hash, hash, 16)) {
            if (authcache.slots[u].when < time(NULL) - entry_lifetime) {
                log_print(LOG_DEBUG, _("authcache_new_user_pass: dropped old cache entry for %s from slot %u"), username_string(user, local_part, domain), u);
                remove_cache_entry(u);
                return NULL;
            } else {
                log_print(LOG_DEBUG, _("authcache_new_user_pass: returning saved entry for %s (%ds old) from slot %u"), username_string(user, local_part, domain), (int)(time(NULL) - authcache.slots[u].when), u);
                return authcontext_copy(authcache.slots[u].A);
            }
        } else
            u = (u + 1) % CACHESLOTS;
    } while (u != u0);
    log_print(LOG_DEBUG, _("authcache_new_user_pass: no entry for %s"), username_string(user, local_part, domain));
    return NULL;
}

/* authcache_save CONTEXT USER LOCALPART DOMAIN PASSWORD CLIENTHOST SERVERHOST
 * Save the given authentication CONTEXT under the given arguments. */
void authcache_save(authcontext A, const char *user, const char *local_part, const char *domain, const char *pass, const char *clienthost, const char *serverhost) {
    unsigned char hash[16];
    unsigned long u;
    authcontext Acopy;

    if (!use_cache)
        return;
    
    /* Add `+cache' to the end of the authcontext name. */
    Acopy = authcontext_copy(A);
    xfree(Acopy->auth);
    Acopy->auth = xmalloc(strlen(A->auth) + sizeof "+cache");
    sprintf(Acopy->auth, "%s+cache", A->auth);

    /* Find a free hash slot. */
    make_arg_hash(hash, user, local_part, domain, pass, clienthost, serverhost);
    
    if (authcache.nfilled + 1 == CACHESLOTS) {
        resize_cache(authcache.nbits + 1);
        log_print(LOG_DEBUG, _("authcache_save: resized cache to %u byte key"), (unsigned)authcache.nbits);
    }

    for (u = hashval(hash, authcache.nbits); authcache.slots[u].A; u = (u + 1) % CACHESLOTS);
    log_print(LOG_DEBUG, _("authcache_save: saved entry for %s in slot %u"), username_string(user, local_part, domain), u);
    memcpy(authcache.slots[u].hash, hash, 16);
    authcache.slots[u].A = Acopy;
    time(&authcache.slots[u].when);
    ++authcache.nfilled;
}
