/*
 * auth_perl.c:
 * Call into a perl subroutine to perform authentication.
 *
 * This is somewhat based on perl.c in the exim distribution.
 *
 * Copyright (c) 2001 Chris Lightfoot. All rights reserved.
 *
 */

static const char rcsid[] = "$Id$";

#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

/* Include files for perl integration. */
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "auth_perl.h"

static PerlInterpreter *auth_perl_interp;

/* auth_perl_init:
 * Initialise the perl interpreter and run its startup code.
 */
extern stringmap config;    /* in main.c */

int auth_perl_init() {
    dSP;
    int argc = 2;
    char *argc[3] = {"auth_perl", "/dev/null", NULL};
    char *startupcode;
    SV *sv;
    STRLEN len;

    /* Obtain perl startup code; this should probably be something like
     * "do '/etc/tpop3d.pl';"
     */
    startupcode = stringmap_find(config, "auth-perl-start");
    if (!startupcode) {
        print_log(LOG_ERR, _("auth_perl_init: auth_perl enabled, but no startup code specified"));
        return 0;
    }
    
    auth_perl_interp = perl_alloc();
    perl_construct(auth_perl_interp);
    perl_parse(auth_perl_interp, xs_init, argc, argv, 0);
    perl_run(auth_perl_interp);

    /* Try to execute the startup code. */
    sv = newSVpv(startupcode, 0);
    PUSHMARK(SP);
    perl_eval_sv(sv, G_SCALAR | G_DISCARD | G_KEEPERR); /* XXX options */
    SvREFCNT_dec(sv);
    if (SvTRUE(ERRSV)) {
        print_log(LOG_ERR, _("auth_perl_init: error executing perl startup code: %s"), SvPV(ERRSV, len));
        perl_destruct(auth_perl_interp);
        perl_free(auth_perl_interp);
        auth_perl_interp = NULL;
        return 0;
    }

    return 1;
}
