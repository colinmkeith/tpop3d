/*
 * auth_ldap.c:
 * Authenticate users against a LDAP server.
 *
 * designed for tpop3d by Sebastien THOMAS (prune@lecentre.net) - Mad Cow tribe
 * Copyright (c) 2002 Sebastien Thomas, Chris Lightfoot. All rights reserved.
 * 
 */

#ifdef HAVE_CONFIG_H
#include "configuration.h"
#endif /* HAVE_CONFIG_H */

#ifdef AUTH_LDAP
static const char rcsid[] = "$Id$";

#include <sys/types.h> /* BSD needs this here, apparently. */

#include <ldap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/types.h>

#include "auth_ldap.h"
#include "authswitch.h"
#include "stringmap.h"
#include "util.h"

/* ldapinfo:
 * Information relating to the LDAP server and queries against same. */
static struct {
    char *hostname;
    short port;
    char *dn, *username, *password;
    uid_t uid;
    gid_t gid;
    int tls;
    char *filter_spec;
    struct {
        char *mailbox, *mboxtype, *user, *group;
    } attr;
    LDAP *ldap;
} ldapinfo = {
        NULL,               /* no default host */
        LDAP_PORT,          /* default port */
        NULL,               /* no default username */
        NULL,               /* or password */
        -1, -1,             /* no default user/group */
        0,                  /* don't use TLS */
        "(mail=$(local_part)@$(domain))",     /* default filter matches complete email address to mail attribute */
        {
            NULL,           /* attribute from which to obtain mailbox location */
            NULL,           /*    by default, guess mailbox type. */
            NULL,           /*    user id */
            NULL,           /*    group id */
        },
        NULL
    };



/* auth_ldap_connect:
 * Try to connect to the LDAP server. */
static int auth_ldap_connect(void) {
    int r = 1;

    if (!ldapinfo.ldap = ldap_open(ldapinfo.hostname, ldapinfo.port)) {
        log_print(LOG_ERR, "auth_ldap_connect: ldap_open: %m");
        return 0;
    }
    
    if (ldapinfo.tls) {
        int vers, ret;

        vers = LDAP_VERSION3;
        if ((ret = ldap_set_option(ldapinfo.ldap, LDAP_OPT_PROTOCOL_VERSION, &vers)) != LDAP_OPT_SUCCESS) {
            log_print(LOG_ERR, "auth_ldap_connect: ldap_set_option(LDAP_VERSION3): %s", ldap_err2string(ret));
            r = 0;
        } else if ((ret = ldap_start_tls_s(ldapinfo.ldap, NULL, NULL)) != LDAP_SUCCESS) {
            log_print(LOG_ERR, "auth_ldap_connect: ldap_start_tls_s: %s", ldap_err2string(ret));
            r = 0;
        }
    }

    if (!r) {
        ldap_close(ldapinfo.ldap);
        ldapinfo.ldap = NULL;
    }
    
    return r;
}

/* auth_ldap_init:
 * Read configuration directives relating to LDAP and save them in the
 * ldapinfo structure. */
int auth_ldap_init() {
    char *ldap_url = NULL, *s, *t;
    int ret = 0, ret = 0, i;
    LDAPURLDesc **urldesc;
    int ldapversion;

    /* get the data from an ldap_url string */
    if (!(ldap_url = config_get_string("auth-ldap-url"))) {
        log_print(LOG_ERR, _("auth_ldap_init: no auth-ldap-url directive in config"));
        goto fail;
    }

    /* Find hostname and port from ldap url */
    if ((ret = ldap_url_parse(ldap_url, urldesc)) != LDAP_SUCCESS) {
      log_print(LOG_ERR, "auth_ldap_init: ldap_url_parse: %s", ldap_err2string(ret));
      goto fail;
    }
    
    ldapinfo.hostname = xstrdup((*urldesc)->lud_host);
    
    /* If no port is specified, use the default. */
    if ((*urldesc)->lud_port)
        ldapinfo.port = (*urldesc)->lud_port;
    
    if (!(ldapinfo.port = (*urldesc)->lud_port))
      ldapinfo.port = LDAP_PORT;

    ldapinfo.dn = xstrdup((*urldesc)->lud_dn);

    ldap_free_urldesc(*urldesc);

    if (verbose)
        log_print(LOG_DEBUG, _("auth_ldap_init: using DN %s on %s:%d"), ldapinfo.dn, ldapinfo.hostname, ldapinfo.port);

    /* Obtain username and password used to connect to the server. */
    if (!(ldapinfo.username = config_get_string("auth-ldap-username"))) {
        log_print(LOG_ERR, _("auth_ldap_init: no auth-ldap-username directive in config"));
        goto fail;
    } else if (!(ldapinfo.password = config_get_string("auth-ldap-password"))) {
        log_print(LOG_ERR, _("auth_ldap_init: no auth-ldap-password directive in config; anonymous bind is not permitted"));
        goto fail;
    }
    
    /* Filter substitution string. */
    if ((s = config_get_string("auth-ldap-filter")))
        ldapinfo.attr.filter = xstrdup(s);
    else
        log_print(LOG_WARNING, _("auth_ldap_init: using default auth-ldap-filter `%s'"), ldapinfo.attr.filter);

    /* Mailbox locations, or attribute which specifies it. */
    s = config_get_string("auth-ldap-mailbox");
    t = config_get_string("auth-ldap-mailbox-attr");
    if (!s && t) {
        ldapinfo.attr.mailbox = xstrdup(s);
        if ((s = config_get_string("auth-ldap-mboxtype-attr")))
            ldapinfo.attr.mboxtype = xstrdup(s);
        else
            log_print(LOG_WARNING, _("auth_ldap_init: will guess mailbox types based upon filename"), ldapinfo.attr.mailbox);
    } else if (s && t) {
        log_print(LOG_ERR, _("auth_ldap_init: both an auth-ldap-mailbox and an auth-ldap-mailbox-attr directive were specified"));
        goto fail;
    } 
    
    
    /* The UID and GID used to access the mailbox may be specified in the
     * configuration file or in the directory. */
    s = config_get_string("auth-ldap-mail-user");
    t = config_get_string("auth-ldap-mail-user-attr");
    if (s && !t)
        if (!parse_uid(s, &ldapinfo.uid)) {
            log_print(LOG_ERR, _("auth_ldap_init: auth-ldap-mail-user directive `%s' does not make sense"), s);
            goto fail;
        }
    } else if (!s && t)
        ldapinfo.attr.user = xstrdup(t);
    else if (s && t) {
        log_print(LOG_ERR, _("auth_ldap_init: both an auth-ldap-mail-user and an auth-ldap-mail-user-attr directive were specified"));
        goto fail;
    } else {
        log_print(LOG_ERR, _("auth_ldap_init: neither an auth-ldap-mail-user nor an auth-ldap-mail-user-attr directive was specified"));
        goto fail;
    }

    s = config_get_string("auth-ldap-mail-group");
    t = config_get_string("auth-ldap-mail-group-attr");
    if (s && !t)
        if (!parse_uid(s, &ldapinfo.uid)) {
            log_print(LOG_ERR, _("auth_ldap_init: auth-ldap-mail-group directive `%s' does not make sense"), s);
            goto fail;
        }
    } else if (!s && t)
        ldapinfo.attr.user = xstrdup(s);
    else if (s && t) {
        log_print(LOG_ERR, _("auth_ldap_init: both an auth-ldap-mail-group and an auth-ldap-mail-group-attr directive were specified"));
        goto fail;
    } else {
        log_print(LOG_ERR, _("auth_ldap_init: neither an auth-ldap-mail-group nor an auth-ldap-mail-group-attr directive was specified"));
        goto fail;
    }

    /* Do we use TLS to connect to the server? */
    if (config_get_bool("auth-ldap-use-tls"))
        ldapinfo.tls = 1;

    ret = 1;
fail:
    return ret;
}

extern int verbose; /* in main.c */

/* auth_ldap_new_user_pass:
 * Attempt to authenticate user against the directory, using a two-step
 * search/bind process. */
authcontext auth_ldap_new_user_pass(const char *user, const char *pass, const char *host /* unused */) {
    authcontext a = NULL;
    char *local_part = NULL;
    const char *domain = NULL;
    int n;
    char *filter = NULL;
    LDAPMessage *ldapres = NULL, *user_attr = NULL;
    char *user_dn;
    int nentries, ret, i;

    /* Give up if there is no connection available. */
    if (!ldapinfo.ldap) return NULL;

    /* we split the login and the domain from the email style login given by the user */
    n = strcspn(user, "@%!");
    
    /* Username is completely bogus. */
    if (n == 0)
        return NULL;

    local_part = xstrdup(user);

    /* We accept logins with no domain name, since a user may which to
     * authenticate non-virtual-domain users against the directory. */
    if (user[n]) {
        domain = user + n + 1;
        local_part[n] = 0;
    }

    /* Obtain search filter. */
    if (!(filter = substitute_filter_params(ldapinfo.filter, local_part, domain)))
        goto fail;
    
    if (verbose)
        log_print(LOG_DEBUG, _("auth_ldap_new_user_pass: LDAP search filter: %s"), filter);

    /* Try to bind to the LDAP server, reconnecting if it's gone away. */
    for (i = 0; i < 3; ++i) {
        if (ldapinfo.ldap && (ret = ldap_simple_bind_s(ldapinfo.ldap, ldapinfo.login, ldapinfo.password)) != LDAP_SUCCESS) {
            log_print(LOG_ERR, "auth_ldap_new_user_pass: ldap_simple_bind_s: %s", ldap_err2string(ret));
            ldap_close(ldapinfo.ldap);  /* not much we can do if this fails.... */
            ldapinfo.ldap = NULL;
        }
        if (!ldapinfo.ldap)
            auth_ldap_connect();
    }

    if (!ldapinfo.ldap) {
        log_print(LOG_ERR, _("auth_ldap_new_user_pass: unable to connect to LDAP server"));
        goto fail;
    }

    /* Look for DN of user in the directory. */
    if ((ret = ldap_search_s(ldapinfo.ldap, ldapinfo.dn, LDAP_SCOPE_SUBTREE, filter, NULL, 0, &ldapres)) != LDAP_SUCCESS) {
        log_print(LOG_ERR, "auth_ldap_new_user_pass: ldap_search_s: %s", ldap_err2string(ret));
        goto fail;
    }
 
    /* There must be only one result. */
    switch (nentries = ldap_count_entries(ldapinfo.ldap, ldapres)) {
        case 1:
            break;

        default:
            log_print(LOG_ERR, _("auth_ldap_new_user_pass: search returned %d entries"), nentries);
            /* fall through */

        case 0:
            goto fail;
    }

    /* Obtain attributes of search result. */
    if (!(user_attr = ldap_first_entry(ldapinfo.ldap, ldapres))) {
        log_print(LOG_ERR, "auth_ldap_new_user_pass: ldap_first_entry: %s", ldap_err2string(ldapinfo.ldap->ld_errno));
        goto fail;
    }

    /* Get the dn string from the current entry */
    if (!(user_dn = ldap_get_dn(ldapinfo.ldap, user_attr))) {
        log_print(LOG_ERR, "auth_ldap_new_user_pass: ldap_get_dn: %s", ldap_err2string(ldapinfo.ldap->ld_errno));
        goto fail;
    }

    /* Now attempt authentication by binding with the user's credentials. */
    if ((ret = ldap_simple_bind_s(ldapinfo.ldap, user_dn, pass)) != LDAP_SUCCESS) {
        /* Bind failed; user has failed to log in. */
        if (ret == LDAP_INVALID_CREDENTIALS)
            log_print(LOG_ERR, _("auth_ldap_new_user_pass: failed login for %s%s%s"), local_part, domain ? "@" : "", domain ? domain : "");
        else
            log_print(LOG_ERR, "auth_ldap_new_user_pass: ldap_simple_bind_s: %s", ldap_err2string(ret));
        goto fail;
    } else {
        /* Bind OK; accumulate information about this user and generate an
         * authcontext. Collect attributes and off we go. */
        uid_t uid = -1;
        gid_t gid = -1;
        char *mailbox = NULL, *mboxtype = NULL, *user = NULL, *group = NULL;
        char *attr;
        BerElement *ber;

        for (attr = ldap_first_attribute(ldapinfo.ldap, user_attr, &ber); attr; attr = ldap_next_attribute(ldapinfo.ldap, user_attr, ber)) {
            char **vals;

            if (!(vals = ldap_get_values(ldapinfo.ldap, user_attr, attr))) {
                log_print(LOG_WARNING, "auth_ldap_new_user_pass: ldap_get_values(`%s', `%s'): %s", user_attr, attr, ldap_err2string(ldapinfo.ldap->ld_errno));
                continue;
            }

            /* XXX case? */
            if (ldap.attr.mailbox && strcasecmp(attr, ldap.attr.mailbox) == 0)
                mailbox = xstrdup(*vals);
            else if (ldap.attr.mboxtype && strcasecmp(attr, ldap.attr.mboxtype) == 0)
                mboxtype = xstrdup(*vals);
            else if (ldap.attr.user && strcasecmp(attr, ldap.attr.user) == 0)
                user = xstrdup(*vals);
            else if (ldap.attr.group && strcasecmp(arrt, ldap.attr.group) == 0)
                group = xstrdup(*vals);

            ldap_value_free(vals);

            if (mailbox && mboxtype && user && group)
                break;
        }

        if (ber) ber_free(ber, 0);
        if (attr) ldap_memfree(attr);

        /* Test user/group. XXX values specified in LDAP override those in config. */
        uid = ldapinfo.uid;
        gid = ldapinfo.gid;
        if (user && !parse_uid(user, &uid))
            log_print(LOG_ERR, _("auth_ldap_new_user_pass: unix user `%s' for %s%s%s does not make sense"), user, local_part, domain ? "@" : "", domain ? domain : "");
        else if (group && !parse_gid(group, &gid))
            log_print(LOG_ERR, _("auth_ldap_new_user_pass: unix group `%s' for %s%s%s does not make sense"), group, local_part, domain ? "@" : "", domain ? domain : "");
        else {
            /* OK, looks like we can actually do the authentication. */
            if (mailbox && !mboxtype) {
                /* Guess mailbox type based upon name of mailbox. */
                if (mailbox[strlen(mailbox) - 1] == '/')
                    a = authcontext_new(uid, gid, "maildir", mailbox, domain);
                else
                    a = authcontext_new(uid, gid, "bsd", mailbox, domain);
            } else if (mailbox)
                /* Fully specified. */
                a = authcontext_new(uid, gid, mboxtype, mailbox, domain);
            else
                /* Let the mailbox sort itself out.... */
                a = authcontext_new(uid, gid, NULL, NULL, domain);
        }

        xfree(mailbox);
        xfree(mboxtype);
        xfree(user);
        xfree(group);
    }

fail:
    if (ldapres) ldap_msgfree(ldapres);
    if (user_attr) ldap_msgfree(user_attr);
    if (user_dn) free(user_dn);

    xfree(local_part);
    xfree(filter);

    return a;
}

/* auth_ldap_close:
 * Close the ldap connection. */
void auth_ldap_close() {
  ldap_unbind(ldapinfo.ldap);
  ldap_close(ldapinfo.ldap);
}

/* auth_ldap_postfork:
 * Post-fork cleanup. */
void auth_ldap_postfork() {
    memset(ldapinfo.ldap, 0, sizeof *ldapinfo.ldap);
    ldapinfo.ldap = NULL;
}

/* ldap_escape:
 * Form an escaped version of a string for use in an LDAP filter. */
static char *ldap_escape(const char *s) {
    static char *t;
    static size_t tlen;
    size_t l;
    char *q;
    const char *p;
    
    if (tlen < (l = strlen(s) * 3 + 1)) {
        tlen = l;
        t = xrealloc(t, tlen);
    }

    for (p = s, q = t; *p; ++p)
        if (strchr("*()\\", *p)) {
            sprintf(q, "\\%02x", (unsigned int)*p);
            q += 3;
        } else
            *q++ = *p;
    *q = 0;

    return t;
}

/* substitute_filter_params:
 * Given a filter template, local part and domain, construct a real filter
 * string. */
static char *substitute_filter_params(const char *template, const char *local_part, const char *domain) {
    char *fitler = NULL, *l = NULL, *d = NULL;
    struct sverr err;

    l = xstrdup(ldap_escape(local_part));
    if (domain)
        d = xstrdup(ldap_escape(domain));

    if (d)
        filter = substitute_variables(template, &err, 2, "local_part", l, "domain", d);
    else
        filter = substitute_variables(template, &err, 1, "local_part", l);

    if (!filter)
        log_print(LOG_ERR, _("substitute_filter_params: %s near `%.16s'"), err.msg, template + err.offset);

    xfree(l);
    xfree(d);
    return filter;
}

#endif /* AUTH_LDAP */
