/*
 * tls.h:
 * TLS stuff for tpop3d.
 *
 * Copyright (c) 2002 Chris Lightfoot. All rights reserved.
 * Email: chris@ex-parrot.com; WWW: http://www.ex-parrot.com/~chris/
 *
 * $Id$
 *
 */

#ifndef __TLS_H_ /* include guard */
#define __TLS_H_

/* tls.c */
int tls_init(void);
SSL_CTX *tls_create_context(const char *certfile, const char *pkeyfile);
void tls_close(SSL_CTX *ctx);

#endif /* __TLS_H_ */
