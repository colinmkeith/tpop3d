/*
 * auth_perl.h:
 *
 * Copyright (c) 2001 Chris Lightfoot.
 *
 * $Id: auth_cdb.h,v 1.15 2005/09/02 19:18:09 colin Exp $
 *
 */

#ifndef __AUTH_CDB_H_ /* include guard */
#define __AUTH_CDB_H_

#ifdef AUTH_CDB

#ifdef HAVE_CONFIG_H
#include "configuration.h"
#endif /* HAVE_CONFIG_H */

#include "authswitch.h"
#include <cdb.h>

// Turn these on or off as you like:
#define USE_BULLETINS  1
#define USE_LAST_LOGIN 1


#define BUFLEN      1024
#define CLOSEIT(X)  cdb_free(&c); close(fd); return(X);
#define USERNAMES_ARE_EMAILS 1

// Option bitmasks:
// NOTE: |= set bitflag, ^= unset bitflag, x & y test x for bitflag y
//       sorry, but I keep forgetting :p
#define O_COMBINED_SPOOL      1
#define O_ALLOW_PLUSSIGN      2
#define O_PLAINTEXT_FALLBACK  4
#define O_ENABLE_BULLETINS    8
#define O_KEEP_LAST_LOGIN    16
#define O_ENABLE_ACL         32
#define O_CASE_SENSITIVE     64
#define O_ALLOW_SUBLOGINS   128

#ifdef USE_BULLETINS
// For BULPERM
#include <sys/types.h>
#include <sys/stat.h>
#define BULPERMS S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP
#define BULLETIN_DIR_NAME ".bulletins"
int copybulletin(char *sysbdir, char *sysbname, char *mboxdrv, char *mailbox);
#endif

#ifdef USE_LAST_LOGIN
#include <sys/types.h>
#include <sys/stat.h>
#define LLPERMS S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP
#endif


#ifdef WANBLIST
int is_blacklisted(char *key, char *clienthost)
int is_whitelisted(char *key, char *clienthost)
#endif

#define ACE_BASE(caller, msg, ...) log_print(LOG_ERR, caller ": Error: " msg, ##__VA_ARGS__);

#define ACE_KEY(msg, ...)    ACE_BASE("auth_cdb:cdbget", msg, ##__VA_ARGS__)
#define ACE_INIT(msg, ...)   ACE_BASE("auth_cdb_init", msg, ##__VA_ARGS__)
#define ACE_AUTH(msg, ...)   ACE_BASE("auth_cdb_authenticate", msg, ##__VA_ARGS__)
#define ACE_LOGIN(msg, ...)  ACE_BASE("auth_cdb_onlogin", msg, ##__VA_ARGS__)
#define ACE_PFORK(msg, ...)  ACE_BASE("auth_cdb_postfork", msg, ##__VA_ARGS__)
#define ACE_CLOSE(msg, ...)  ACE_BASE("auth_cdb_close", msg, ##__VA_ARGS__)

#ifdef DEBUG_VERBOSE
#define ACD_BASE(caller, msg, ...) log_print(LOG_DEBUG, caller ": " msg, ##__VA_ARGS__);

#define ACD_KEY(msg, ...)    ACD_BASE("auth_cdb:cdbget", msg, ##__VA_ARGS__)
#define ACD_INIT(msg, ...)   ACD_BASE("auth_cdb_init", msg, ##__VA_ARGS__)
#define ACD_AUTH(msg, ...)   ACD_BASE("auth_cdb_authenticate", msg, ##__VA_ARGS__)
#define ACD_LOGIN(msg, ...)  ACD_BASE("auth_cdb_onlogin", msg, ##__VA_ARGS__)
#define ACD_PFORK(msg, ...)  ACD_BASE("auth_cdb_postfork", msg, ##__VA_ARGS__)
#define ACD_CLOSE(msg, ...)  ACD_BASE("auth_cdb_close", msg, ##__VA_ARGS__)

#else

#define ACD_KEY(...)
#define ACD_INIT(...)
#define ACD_AUTH(...)
#define ACD_LOGIN(...)
#define ACD_PFORK(...)
#define ACD_CLOSE(...)

#endif

#ifdef USE_LAST_LOGIN
#define LAST_LOGIN_FILE   ".lastlogin"
int update_last_login(char *mbox, char *srcip);
#define ACE_UPDLL(msg, ...)    ACE_BASE("auth_cdb:update_last_login: Error", msg, ##__VA_ARGS__)
#ifdef DEBUG_VERBOSE
#define ACD_UPDLL(msg, ...)    ACD_BASE("auth_cdb:update_last_login: ", msg, ##__VA_ARGS__)
#else
#define ACD_UPDLL(...)
#endif
#endif


#define XMALLOC(type, len) (type *)xmalloc(sizeof(type) * (len))

/* auth_cdb.c */
int auth_cdb_init(void);
authcontext auth_cdb_new_apop(const char *user, const char *local_part, const char *domain, const char *timestamp, const unsigned char *digest, const char *clienthost, const char *serverhost);
authcontext auth_cdb_new_user_pass(const char *user, const char *local_part, const char *domain, const char *pass, const char *clienthost, const char *serverhost);
authcontext auth_cdb_authenticate(char *user, const char *local_part, const char *domain, const char *timestamp, const unsigned char *digest, const char *clienthost, const char *serverhost);
void auth_cdb_onlogin(const authcontext A, const char *clienthost, const char *serverhost);
void auth_cdb_close(void);
// void auth_cdb_postfork(void);
int cdbget(char *file, char *key, char *buf, unsigned int buflen);

#endif /* AUTH_CDB */
#endif /* __AUTH_CDB_H_ */
