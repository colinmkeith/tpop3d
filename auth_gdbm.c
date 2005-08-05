/*
 * auth_gdbm.c:
 * Authenticate users using a GNU dbm file
 *
 * Based on auth_flatfile.h by Angel Marin, designed for tpop3d by
 * Daniel Tiefnig at Inode, Austria. <d.tiefnig@inode.at>
 *
 * Copyright (c) 2004 Daniel Tiefnig. All rights reserved. This
 * software is free software, you can modify and/or redistribute
 * it as tpop3d itself. See the file COPYING in the base directory
 * of your tpop3d distribution.
 */

#ifdef HAVE_CONFIG_H
#include "configuration.h"
#endif /* HAVE_CONFIG_H */

#ifdef AUTH_GDBM

#include <sys/types.h>

#ifdef HAVE_CRYPT_H /* XXX */
#include <crypt.h>
#endif

#include <unistd.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <gdbm.h>

#include "auth_gdbm.h"
#include "authswitch.h"
#include "password.h"
#include "config.h"
#include "util.h"

static gid_t virtual_gid;
static uid_t virtual_uid;
static char *user_passwd_file;
GDBM_FILE dbf;
int persistent;

/* auth_gdbm_init:
 * Initialise the driver. Reads the config directives. */
int auth_gdbm_init() {
    char *s;

    /* Obtain uid to use */
    if ((s = config_get_string("auth-gdbm-mail-user"))) {
        if (!parse_uid(s, &virtual_uid)) {
            log_print(LOG_ERR, _("auth_gdbm_init: auth-gdbm-mail-user directive `%s' does not make sense"), s);
            return 0;
        }
    } else {
        log_print(LOG_ERR, _("auth_gdbm_init: no auth-gdbm-mail-user directive in config"));
        return 0;
    }

    /* Obtain gid to use */
    if ((s = config_get_string("auth-gdbm-mail-group"))) {
        if (!parse_gid(s, &virtual_gid)) {
            log_print(LOG_ERR, _("auth_gdbm_init: auth-gdbm-mail-group directive `%s' does not make sense"), s);
            return 0;
        }
    } else {
        log_print(LOG_ERR, _("auth_gdbm_init: no auth-gdbm-mail-group directive in config"));
        return 0;
    }

    /* Obtain path to passwd file */
    if ((s = config_get_string("auth-gdbm-passwd-file"))) {
        user_passwd_file = s;
    } else {
        log_print(LOG_ERR, _("auth_gdbm_init: no auth-gdbm-passwd-file directive in config"));
        return 0;
    }

    /* persistent GDBM filehandle? */
    if (config_get_bool("auth-gdbm-persistent")) {
        persistent = 1;
        if((dbf=gdbm_open(user_passwd_file, 0, GDBM_READER, 0644, 0)) == NULL) {
            log_print(LOG_ERR, _("auth_gdbm_init: could not open GNU dbm file"));
            return 0;
        }
    } else {
        persistent = 0;
    }

    return 1;
}

/* auth_gdbm_new_user_pass:
 * Attempt to authenticate user and pass using a GNU dbm file,
 * as configured at compile-time.
 * This is a virtual-domains authenticator. */
authcontext auth_gdbm_new_user_pass(const char *user, const char *local_part, const char *domain, const char *pass, const char *clienthost /* unused */, const char *serverhost /* unused */) {
    authcontext a = NULL;
    char *who, *address;
    datum key, value;

    if (!local_part) return NULL;
    
    who = username_string(user, local_part, domain);

    address = xmalloc(strlen(local_part) + strlen(domain) +2);
    sprintf(address, "%s@%s", local_part, domain);
    key.dptr = address;
    key.dsize = strlen(address);

    if (persistent) {
        value = gdbm_fetch(dbf,key);
    } else {
        if((dbf=gdbm_open(user_passwd_file, 0, GDBM_READER, 0644, 0)) == NULL) {
            log_print(LOG_ERR, _("auth_gdbm_init: could not open GNU dbm file"));
            return 0;
        }
        value = gdbm_fetch(dbf,key);
        gdbm_close(dbf);
    }

    xfree(address);
    if(value.dptr == NULL) {
        log_print(LOG_ERR, _("auth_gdbm_new_user_pass: could not find user %s"), who);
        return a;
    }

    if (check_password(who, value.dptr, pass, "{crypt}"))
        a = authcontext_new(virtual_uid, virtual_gid, NULL, NULL, NULL);
    else
        log_print(LOG_ERR, _("auth_gdbm_new_user_pass: failed login for %s"), who);

    xfree(value.dptr);

    return a;
}

/* auth_gdbm_new_apop:
 * Attempt to authenticate user via APOP using a GNU dbm file,
 * as configured at compile-time.
 * This is a virtual-domains authenticator. */
authcontext auth_gdbm_new_apop(const char *user, const char *local_part, const char *domain, const char *timestamp, const unsigned char *digest, const char *clienthost /* unused */, const char *serverhost /* unused */) {
    authcontext a = NULL;
    char *who, *address;
    datum key, value;

    if (!local_part) return NULL;

    who = username_string(user, local_part, domain);

    address = xmalloc(strlen(local_part) + strlen(domain) +2);
    sprintf(address, "%s@%s", local_part, domain);
    key.dptr = address;
    key.dsize = strlen(address);

    if (persistent) {
        value = gdbm_fetch(dbf,key);
    } else {
        if((dbf=gdbm_open(user_passwd_file, 0, GDBM_READER, 0644, 0)) == NULL) {
            log_print(LOG_ERR, _("auth_gdbm_init: could not open GNU dbm file"));
            return 0;
        }
        value = gdbm_fetch(dbf,key);
        gdbm_close(dbf);
    }

    xfree(address);
    if(value.dptr == NULL) {
        log_print(LOG_ERR, _("auth_gdbm_new_apop: could not find user %s"), who);
        return a;
    }

    if (check_password_apop(who, value.dptr, timestamp, digest))
        a = authcontext_new(virtual_uid, virtual_gid, NULL, NULL, NULL);
    else
        log_print(LOG_ERR, _("auth_gdbm_new_apop: failed login for %s"), who);

    xfree(value.dptr);

    return a;
}

void auth_gdbm_postfork() {
    if (persistent)
        gdbm_close(dbf);
}

void auth_gdbm_close() {
    if (persistent)
        gdbm_close(dbf);
}

#endif /* AUTH_GDBM */
