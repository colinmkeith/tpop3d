/*
 * cfgdirectives.c:
 * List of valid config directives.
 *
 * This is ugly; it would be nice to pick this information automatically
 * somehow from the source, but that's a matter for another day.
 *
 * Copyright (c) 2001 Chris Lightfoot. All rights reserved.
 *
 */

static const char rcsid[] = "$Id$";

#ifdef HAVE_CONFIG_H
#include "configuration.h"
#endif /* HAVE_CONFIG_H */

#include <stdlib.h>

char *cfgdirectives[] = {
    /* global directives */
    "listen-address",
    "max-children",
    "append-domain",
    "timeout-seconds",
    "mailbox",

#ifdef AUTH_PAM
    /* auth-pam options */
    "auth-pam-enable",
    "auth-pam-facility",
    "auth-pam-mailbox",
    "auth-pam-mail-group",
#endif

#ifdef AUTH_PASSWD
    /* auth-passwd options */
    "auth-passwd-enable",
    "auth-passwd-mailbox",
    "auth-passwd-mail-group",
#endif

#ifdef AUTH_MYSQL
    /* auth-mysql options */
    "auth-mysql-enable",
    "auth-mysql-username",
    "auth-mysql-password",
    "auth-mysql-database",
    "auth-mysql-hostname",
    "auth-mysql-mail-group",
#endif /* AUTH_MYSQL */

#ifdef AUTH_OTHER
    "auth-other-enable",
    "auth-other-program",
    "auth-other-user",
    "auth-other-group",
    "auth-other-timeout",
#endif /* AUTH_OTHER */
 
#ifdef AUTH_PERL
    "auth-perl-enable",
    "auth-perl-start",
    "auth-perl-finish",
    "auth-perl-apop",
    "auth-perl-pass",
#endif /* AUTH_PERL */
    
    /* final entry must be NULL */
    NULL};

int is_cfgdirective_valid(const char *s) {
    char **t;
    for (t = cfgdirectives; *t; ++t)
        if (strcmp(s, *t) == 0) return 1;
    return 0;
}
