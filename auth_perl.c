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

#include "config.h"
#include "auth_perl.h"
#include "stringmap.h"
#include "util.h"

/* Include files for perl integration. */
#undef PACKAGE      /* work around bad perl/autoconf interaction */
#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>

static PerlInterpreter *perl_interp;
char *apop_sub, *pass_sub, *onlogin_sub;    /* Names of functions we call. */

#ifndef ERRSV
#define ERRSV (GvSV(errgv))
#endif

/* xs_log_print:
 * Perl interface to tpop3d's logging. */
XS(xs_log_print)
{
    dXSARGS;
    char  *str;
    STRLEN len;
    
    if (items != 1) croak("Usage: TPOP3D::log_print(string)");

    str = SvPV(ST(0), len);
    log_print(LOG_INFO, "auth_perl: (perl code): %s", str);
}

/* xs_init:
 * Start up XS code in perl. */
extern void boot_DynaLoader(CV *cv);

void xs_init(void) {
    char *file = __FILE__;
    newXS("DynaLoader::boot_DynaLoader", boot_DynaLoader, file);
    newXS("TPOP3D::log_print", xs_log_print, file);
}

/* auth_perl_init:
 * Initialise the perl interpreter and run its startup code. */
extern stringmap config;    /* in main.c */

int auth_perl_init(void) {
    dSP;
    int argc = 2;
    char *argv[3] = {"auth_perl", "/dev/null", NULL};
/*   char *argv[4] = {"auth_perl", "-e", "$ENV{TPOP3D_CONTEXT} = 'auth_perl';", NULL}; */
    char *startupcode, *s;
    SV *sv;
    STRLEN len;

    /* Obtain perl startup code; this should probably be something like
     * "do '/etc/tpop3d.pl';" */
    if (!(s = config_get_string("auth-perl-start"))) {
        log_print(LOG_ERR, _("auth_perl_init: auth_perl enabled, but no startup code specified"));
        return 0;
    } else startupcode = s;

    if ((s = config_get_string("auth-perl-apop")))
        apop_sub = s;
    if ((s = config_get_string("auth-perl-pass")))
        pass_sub = s;
    if ((s = config_get_string("auth-perl-onlogin")))
        onlogin_sub = s;
    if (!apop_sub && !pass_sub && !onlogin_sub) {
        log_print(LOG_ERR, _("auth_perl_init: auth_perl enabled but no subroutines supplied"));
        return 0;
    }

    /* Put a useful string into the environment. */
    putenv(strdup("TPOP3D_CONTEXT=auth_perl"));

    /* Create and start up perl interpreter. */
    perl_interp = perl_alloc();
    perl_construct(perl_interp);
    perl_parse(perl_interp, xs_init, argc, argv, 0);
    perl_run(perl_interp);

    /* Try to execute the startup code. */
    sv = newSVpv(startupcode, 0);
    PUSHMARK(SP);
    perl_eval_sv(sv, G_SCALAR | G_DISCARD | G_KEEPERR); /* XXX what do the options actually mean? */
    SvREFCNT_dec(sv);
    if (SvTRUE(ERRSV)) {
        log_print(LOG_ERR, _("auth_perl_init: error executing perl start code: %s"), SvPV(ERRSV, len));
        perl_destruct(perl_interp);
        perl_free(perl_interp);
        perl_interp = NULL;
        return 0;
    }

    return 1;
}

/* auth_perl_postfork:
 * Post-fork cleanup. */
void auth_perl_postfork(void) {
    perl_interp = NULL; /* XXX */
}

/* auth_perl_close:
 * Shut down the perl interpreter. */
void auth_perl_close(void) {
    if (perl_interp) {
        /* There may be code to execute on shutdown. */
        char *s;
        if ((s = config_get_string("auth-perl-finish"))) {
            dSP;
            SV *sv;
            STRLEN len;
            sv = newSVpv(s, 0);
            PUSHMARK(SP);
            perl_eval_sv(sv, G_SCALAR | G_DISCARD | G_KEEPERR);
            SvREFCNT_dec(sv);
            if (SvTRUE(ERRSV))
                log_print(LOG_ERR, _("auth_perl_close: error executing perl finish code: %s"), SvPV(ERRSV, len));
        }
        perl_destruct(perl_interp);
        perl_free(perl_interp);
        perl_interp = NULL;
    }
}

/* auth_perl_callfn:
 * Calls a perl function, passing the parameters in as a reference to a hash,
 * expecting a reference to a hash to be returned; it converts this into a
 * stringmap and returns it to the caller. */
stringmap auth_perl_callfn(const char *perlfn, const int nvars, ...) {
    dSP;
    HV *hash_in, *hash_out;
    SV *hashref_in, *hashref_out;
    va_list ap;
    int i, items;
    stringmap s = NULL;

    if (!perl_interp) return NULL;
    
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
        log_print(LOG_ERR, _("auth_perl_callfn: perl function %s: %s"), perlfn, SvPV(ERRSV, len));
    } else if (!SvOK(hashref_out)) {
        /* Other sort of error. */
        log_print(LOG_ERR, _("auth_perl_callfn: perl function %s: failure return"), perlfn);
    } else if (SvTYPE(SvRV(hashref_out)) != SVt_PVHV) {
        /* Yet a third sort of error. */
        log_print(LOG_ERR, _("auth_perl_callfn: perl function %s: returned value was not a reference to a hash"), perlfn);
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
            char *k = xmalloc(len + 1);
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
 * auth_other_new_apop. */
authcontext auth_perl_new_apop(const char *name, const char *local_part, const char *domain, const char *timestamp, const unsigned char *digest, const char *host) {
#define MISSING(k)     do { log_print(LOG_ERR, _("auth_perl_new_apop: missing key `%s' in response"), (k)); goto fail; } while(0)
#define INVALID(k, v)  do { log_print(LOG_ERR, _("auth_perl_new_apop: invalid value `%s' for key `%s' in response"), (v), (k)); goto fail; } while(0)
    char digeststr[33];
    char *p;
    const unsigned char *q;
    stringmap S;
    item *I;
    authcontext a = NULL;
 
    if (!apop_sub)
        return NULL;
    
    for (p = digeststr, q = digest; q < digest + 16; p += 2, ++q)
        sprintf(p, "%02x", (unsigned int)*q);

    if (local_part && domain) {
        if (!(S = auth_perl_callfn(apop_sub, 7, "method", "APOP", "user", name, "local_part", local_part, "domain", domain, "timestamp", timestamp, "digest", digeststr, "clienthost", host)))
            return NULL;
    } else if (!(S = auth_perl_callfn(apop_sub, 5, "method", "APOP", "user", name, "timestamp", timestamp, "digest", digeststr, "clienthost", host)))
        return NULL;

    I = stringmap_find(S, "logmsg");
    if (I) log_print(LOG_INFO, "auth_perl_new_apop: (perl code): %s", (char*)I->v);

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

        a = authcontext_new(uid, gid, mboxdrv, mailbox, pw->pw_dir);
    } else if (strcmp((char*)I->v, "NO") != 0) INVALID("result", (char*)I->v);
        
fail:
    stringmap_delete_free(S);
    return a;
#undef MISSING
#undef INVALID
}

/* auth_perl_new_user_pass:
 * Attempt to authenticate a user using USER/PASS, via a perl subroutine. */
authcontext auth_perl_new_user_pass(const char *user, const char *local_part, const char *domain, const char *pass, const char *host) {
#define MISSING(k)     do { log_print(LOG_ERR, _("auth_perl_new_user_pass: missing key `%s' in response"), (k)); goto fail; } while(0)
#define INVALID(k, v)  do { log_print(LOG_ERR, _("auth_perl_new_user_pass: invalid value `%s' for key `%s' in response"), (v), (k)); goto fail; } while(0)
    stringmap S;
    item *I;
    authcontext a = NULL;

    if (!pass_sub)
        return NULL;

    if (local_part && domain) {
        if (!(S = auth_perl_callfn(pass_sub, 6, "method", "PASS", "user", user, "local_part", local_part, "domain", domain, "pass", pass, "clienthost", host)))
            return NULL;
    } else if (!(S = auth_perl_callfn(pass_sub, 4, "method", "PASS", "user", user, "pass", pass, "clienthost", host)))
        return NULL;
    
    if ((I = stringmap_find(S, "logmsg")))
        log_print(LOG_INFO, "auth_perl_new_user_pass: (perl code): %s", (char*)I->v);

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

        a = authcontext_new(uid, gid, mboxdrv, mailbox, pw->pw_dir);
    } else if (strcmp((char*)I->v, "NO") != 0) INVALID("result", (char*)I->v);
        
fail:
    stringmap_delete_free(S);
    return a;
#undef MISSING
#undef INVALID
}

/* auth_perl_onlogin:
 * Pass details of a successful login to a perl subroutine. */
void auth_perl_onlogin(const authcontext A, const char *host) {
    stringmap S;
    item *I;

    if (!onlogin_sub || !(S = auth_perl_callfn(onlogin_sub, 5, "method", "ONLOGIN", "user", A->user, "local_part", A->local_part, "domain", A->domain, "clienthost", host)))
        return;
    
    if ((I = stringmap_find(S, "logmsg")))
        log_print(LOG_INFO, "auth_perl_onlogin: (perl code): %s", (char*)I->v);

    stringmap_delete_free(S);
}

#endif /* AUTH_PERL */
