/*
 * auth_perl.c:
 * Call into a perl subroutine to perform authentication.
 *
 * This is somewhat based on perl.c in the exim distribution.
 *
 * Copyright (c) 2001 Chris Lightfoot. All rights reserved.
 *
 */

#ifdef HAVE_CONFIG_H
#include "configuration.h"
#endif /* HAVE_CONFIG_H */

#ifdef AUTH_PERL

static const char rcsid[] = "$Id$";

#include <sys/types.h>

#include <pwd.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>

#include "auth_perl.h"
#include "stringmap.h"
#include "util.h"

/* Include files for perl integration. */
#undef PACKAGE      /* work around bad perl/autoconf interaction */
#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>

static PerlInterpreter *auth_perl_interp;
char *auth_perl_apop, *auth_perl_pass;      /* Names of functions we call. */

#ifndef ERRSV
#define ERRSV (GvSV(errgv))
#endif

/* xs_print_log:
 * Perl interface to tpop3d's logging.
 */
XS(xs_print_log)
{
    dXSARGS;
    char  *str;
    STRLEN len;
    
    if (items != 1) croak("Usage: TPOP3D::print_log(string)");

    str = SvPV(ST(0), len);
    print_log(LOG_INFO, "auth_perl: (perl code): %s", str);
}

/* xs_init:
 * Start up XS code in perl.
 */
extern void boot_DynaLoader(CV *cv);

void xs_init(void) {
    char *file = __FILE__;
    newXS("DynaLoader::boot_DynaLoader", boot_DynaLoader, file);
    newXS("TPOP3D::print_log", xs_print_log, file);
}

/* auth_perl_init:
 * Initialise the perl interpreter and run its startup code.
 */
extern stringmap config;    /* in main.c */

int auth_perl_init() {
    dSP;
    int argc = 2;
    char *argv[3] = {"auth_perl", "/dev/null", NULL};
/*   char *argv[4] = {"auth_perl", "-e", "$ENV{TPOP3D_CONTEXT} = 'auth_perl';", NULL}; */
    item *I;
    char *startupcode;
    SV *sv;
    STRLEN len;

    /* Obtain perl startup code; this should probably be something like
     * "do '/etc/tpop3d.pl';"
     */
    if (!(I = stringmap_find(config, "auth-perl-start"))) {
        print_log(LOG_ERR, _("auth_perl_init: auth_perl enabled, but no startup code specified"));
        return 0;
    } else startupcode = I->v;

    if ((I = stringmap_find(config, "auth-perl-apop"))) auth_perl_apop = I->v;
    if ((I = stringmap_find(config, "auth-perl-pass"))) auth_perl_pass = I->v;
    if (!auth_perl_apop && !auth_perl_pass) {
        print_log(LOG_ERR, _("auth_perl_init: auth_perl enabled but no authenticator subroutines supplied"));
        return 0;
    }

    /* Put a useful string into the environment. */
    putenv(strdup("TPOP3D_CONTEXT=auth_perl"));

    /* Create and start up perl interpreter. */
    auth_perl_interp = perl_alloc();
    perl_construct(auth_perl_interp);
    perl_parse(auth_perl_interp, xs_init, argc, argv, 0);
    perl_run(auth_perl_interp);

    /* Try to execute the startup code. */
    sv = newSVpv(startupcode, 0);
    PUSHMARK(SP);
    perl_eval_sv(sv, G_SCALAR | G_DISCARD | G_KEEPERR); /* XXX what do the options actually mean? */
    SvREFCNT_dec(sv);
    if (SvTRUE(ERRSV)) {
        print_log(LOG_ERR, _("auth_perl_init: error executing perl start code: %s"), SvPV(ERRSV, len));
        perl_destruct(auth_perl_interp);
        perl_free(auth_perl_interp);
        auth_perl_interp = NULL;
        return 0;
    }

    return 1;
}

/* auth_perl_close:
 * Shut down the perl interpreter.
 */
void auth_perl_close() {
    if (auth_perl_interp) {
        /* There may be code to execute on shutdown. */
        item *I;
        if ((I = stringmap_find(config, "auth-perl-finish"))) {
            dSP;
            SV *sv;
            STRLEN len;
            sv = newSVpv(I->v, 0);
            PUSHMARK(SP);
            perl_eval_sv(sv, G_SCALAR | G_DISCARD | G_KEEPERR);
            SvREFCNT_dec(sv);
            if (SvTRUE(ERRSV))
                print_log(LOG_ERR, _("auth_perl_close: error executing perl finish code: %s"), SvPV(ERRSV, len));
        }
        perl_destruct(auth_perl_interp);
        perl_free(auth_perl_interp);
        auth_perl_interp = NULL;
    }
}

/* auth_perl_callfn:
 * Calls a perl function, passing the parameters in as a reference to a hash,
 * expecting a reference to a hash to be returned; it converts this into a
 * stringmap and returns it to the caller.
 */
stringmap auth_perl_callfn(const char *perlfn, const int nvars, ...) {
    dSP;
    HV *hash_in, *hash_out;
    SV *hashref_in, *hashref_out;
    va_list ap;
    int i, items;
    stringmap s = NULL;

    if (!auth_perl_interp) return NULL;
    
    hash_in = newHV();

    /* Fill the hash with the passed values. */
    va_start(ap, nvars);

    for (i = 0; i < nvars; ++i) {
        char *key, *val;
        SV *sv;
        key = va_arg(ap, char*);
        val = va_arg(ap, char*);
        sv = newSVpv(val, 0);
        hv_store(hash_in, key, strlen(key), sv, 0);
    }

    va_end(ap);

    /* Make a reference to the hash. */
    hashref_in = newRV_noinc((SV*)hash_in); /* XXX inc/noinc? */

    /* Call the function. */
    ENTER;
    SAVETMPS;
    PUSHMARK(SP);
    XPUSHs(hashref_in);
    PUTBACK;
    items = perl_call_pv((char*)perlfn, G_SCALAR | G_EVAL);
    SPAGAIN;
    hashref_out = POPs;
    PUTBACK;
    if (SvTRUE(ERRSV)) {
        /* Error. */
        STRLEN len;
        print_log(LOG_ERR, _("auth_perl_callfn: perl function %s: %s"), perlfn, SvPV(ERRSV, len));
    } else if (!SvOK(hashref_out)) {
        /* Other sort of error. */
        print_log(LOG_ERR, _("auth_perl_callfn: perl function %s: failure return"), perlfn);
    } else if (SvTYPE(SvRV(hashref_out)) != SVt_PVHV) {
        /* Yet a third sort of error. */
        print_log(LOG_ERR, _("auth_perl_callfn: perl function %s: returned value was not a reference to a hash"), perlfn);
    } else {
        /* Damn and all, it worked! (Maybe) */
        char *key;
        I32 len;
        SV *val;
        hash_out = (HV*)SvRV(hashref_out);
        s = stringmap_new();

        /* Transfer contents of hash into s. */
        hv_iterinit(hash_out);
        while ((val = hv_iternextsv(hash_out, &key, &len))) {
            char *k = (char*)malloc(len + 1);
            STRLEN len2;
            strcpy(k, key);
            stringmap_insert(s, k, item_ptr(strdup(SvPV(val, len2))));
        }
    }

    FREETMPS;
    LEAVE;

    return s;
}

/* auth_perl_new_apop:
 * Attempt to authenticate a user using APOP, via a perl subroutine. Much like
 * auth_other_new_apop.
 */
authcontext auth_perl_new_apop(const char *name, const char *timestamp, const unsigned char *digest, const char *host) {
#define MISSING(k)     do { print_log(LOG_ERR, _("auth_perl_new_apop: missing key `%s' in response"), (k)); goto fail; } while(0)
#define INVALID(k, v)  do { print_log(LOG_ERR, _("auth_perl_new_apop: invalid value `%s' for key `%s' in response"), (v), (k)); goto fail; } while(0)
    char digeststr[33];
    char *p;
    const unsigned char *q;
    stringmap S;
    item *I;
    authcontext a = NULL;
 
    for (p = digeststr, q = digest; q < digest + 16; p += 2, ++q)
        sprintf(p, "%02x", (unsigned int)*q);
    if (!auth_perl_apop ||
        !(S = auth_perl_callfn(auth_perl_apop, 5, "method", "APOP", "user", name, "timestamp", timestamp, "digest", digeststr, "clienthost", host)))
        return NULL;

    I = stringmap_find(S, "logmsg");
    if (I) print_log(LOG_INFO, "auth_perl_new_apop: (perl code): %s", (char*)I->v);

    I = stringmap_find(S, "result");
    if (!I) MISSING("result");
    
    if (strcmp((char*)I->v, "YES") == 0) {
        uid_t uid;
        gid_t gid;
        struct passwd *pw;
        char *mailbox = NULL, *mboxdrv = NULL, *domain = NULL;

        I = stringmap_find(S, "uid");
        if (!I) MISSING("uid");
        else if (!parse_uid(I->v, &uid)) INVALID("uid", (char*)I->v);
 
        pw = getpwuid(uid);
        if (!pw) INVALID("uid", (char*)I->v);
       
        I = stringmap_find(S, "gid");
        if (!I) MISSING("gid");
        else if (!parse_gid(I->v, &gid)) INVALID("gid", (char*)I->v);

        I = stringmap_find(S, "mailbox");
        if (I) mailbox = (char*)I->v;

        I = stringmap_find(S, "mboxtype");
        if (I) mboxdrv = (char*)I->v;

        I = stringmap_find(S, "domain");
        if (I) domain = (char*)I->v;

        a = authcontext_new(uid, gid, mboxdrv, mailbox, pw->pw_dir, domain);
    } else if (strcmp((char*)I->v, "NO") != 0) INVALID("result", (char*)I->v);
        
fail:
    stringmap_delete_free(S);
    return a;
#undef MISSING
#undef INVALID
}

/* auth_perl_new_user_pass:
 * Attempt to authenticate a user using USER/PASS, via a perl subroutine.
 */
authcontext auth_perl_new_user_pass(const char *user, const char *pass, const char *host) {
#define MISSING(k)     do { print_log(LOG_ERR, _("auth_perl_new_user_pass: missing key `%s' in response"), (k)); goto fail; } while(0)
#define INVALID(k, v)  do { print_log(LOG_ERR, _("auth_perl_new_user_pass: invalid value `%s' for key `%s' in response"), (v), (k)); goto fail; } while(0)
    stringmap S;
    item *I;
    authcontext a = NULL;

    if (!auth_perl_pass || !(S = auth_perl_callfn(auth_perl_pass, 4, "method", "PASS", "user", user, "pass", pass, "clienthost", host)))
        return NULL;
    
    if ((I = stringmap_find(S, "logmsg")))
        print_log(LOG_INFO, "auth_perl_new_user_pass: (perl code): %s", (char*)I->v);

    if (!(I = stringmap_find(S, "result"))) MISSING("result");
    
    if (strcmp((char*)I->v, "YES") == 0) {
        uid_t uid;
        gid_t gid;
        struct passwd *pw;
        char *mailbox = NULL, *mboxdrv = NULL, *domain = NULL;

        I = stringmap_find(S, "uid");
        if (!I) MISSING("uid");
        else if (!parse_uid(I->v, &uid)) INVALID("uid", (char*)I->v);
 
        pw = getpwuid(uid);
        if (!pw) INVALID("uid", (char*)I->v);
       
        I = stringmap_find(S, "gid");
        if (!I) MISSING("gid");
        else if (!parse_gid(I->v, &gid)) INVALID("gid", (char*)I->v);

        I = stringmap_find(S, "mailbox");
        if (I) mailbox = (char*)I->v;

        I = stringmap_find(S, "mboxtype");
        if (I) mboxdrv = (char*)I->v;

        I = stringmap_find(S, "domain");
        if (I) domain = (char*)I->v;

        a = authcontext_new(uid, gid, mboxdrv, mailbox, pw->pw_dir, domain);
    } else if (strcmp((char*)I->v, "NO") != 0) INVALID("result", (char*)I->v);
        
fail:
    stringmap_delete_free(S);
    return a;
#undef MISSING
#undef INVALID
}

#endif
