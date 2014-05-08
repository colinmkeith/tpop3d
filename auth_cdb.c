/*
 * auth_cdb.c:
 *
 * Copyright (c) 2005 Colin Keith, Hagen Software Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
#include "configuration.h"
#endif /* HAVE_CONFIG_H */

#ifdef AUTH_CDB

static const char rcsid[] = "$Id$";

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <fcntl.h>
#include <dirent.h>

#include "config.h"
#include "auth_cdb.h"
#include "password.h"
#include "util.h"

uid_t uid;
gid_t gid;
char *homedir;
char *userfile;
char *spoolfile;
char *bulldir;
#ifdef WANBLIST
char *acl_wl;
char *acl_bl;
#endif
short options;

/* {{{ int auth_cdb_init(void) */
int auth_cdb_init(void){
    char *s;
    struct stat *sb = NULL;
    struct passwd *pw = NULL;
    struct group *gr = NULL;
    char isusername = 0;
    char *p;

    bulldir   = NULL;
    homedir   = NULL;
    userfile  = NULL;
    spoolfile = NULL;
#ifdef WANBLIST
    acl_wl    = NULL;
    acl_bl    = NULL;
#endif
    options = 0;

    if(config_get_bool("auth-cdb-allow-plus-sign"))
      options |= O_ALLOW_PLUSSIGN;

    if(config_get_bool("auth-cdb-plaintext-fallback"))
      options |= O_PLAINTEXT_FALLBACK;

    if(config_get_bool("auth-cdb-allow-sublogins"))
      options |= O_ALLOW_SUBLOGINS;

#ifdef USE_BULLETINS
    if(config_get_bool("auth-cdb-enable-bulletins"))
      options |= O_ENABLE_BULLETINS;
#endif

#ifdef USE_LAST_LOGIN
    if(config_get_bool("auth-cdb-keep-last-login"))
      options |= O_KEEP_LAST_LOGIN;
#endif

#ifdef WANBLIST
    if(config_get_bool("auth-cdb-enable-acl"))
      options |= O_ENABLE_ACL;
#endif

    if(config_get_bool("auth-cdb-case-sensitive-usernames"))
      options |= O_CASE_SENSITIVE;

    /* {{{ Get the user account underwhich to run: */
    /* Did we define anything? No, error. */
    if ((s = config_get_string("auth-cdb-mail-user")) == NULL){
        ACE_INIT("No username/uid defined.")
        return 0;
    }

    ACD_INIT("auth-cdb-mail-user defined.")
    p = s;
    while(p != NULL){
      if(*p < '0' || *p > '9'){
        isusername = 1;
        break;
      }
      p++;
    }

    /* {{{ Is it a username? */
    if(isusername){
        ACD_INIT("Checking if user '%s' is valid.", s)

        if((pw = getpwnam(s)) == NULL){
            ACE_INIT("Username '%s' invalid", s)
            return 0;
        }
        ACD_INIT("Username %s valid.", s)

        uid = pw->pw_uid;
        gid = pw->pw_gid;
    } /* }}} */

    /* {{{ Otherwise its a UID: */
    else {
        uid = (uid_t)atoi(s);
        ACD_INIT("Checking if UID %d is valid.", uid)

        if((pw = getpwuid(uid)) == NULL){
            ACE_INIT("UID %d is invalid.", uid)
            return 0;
        }
        ACD_INIT("UID %d is valid.", uid)
        gid = pw->pw_gid;
    } /* }}} */
    /* }}} */

    /* {{{ Do we have a separate group/GID? */
    if ((s = config_get_string("auth-cdb-mail-group")) != NULL){
        ACD_INIT("Groupname/GID specified. Validating.")

        isusername = 0;
        p = s;
        while(p != NULL){
          if(*p < '0' || *p > '9'){
            isusername = 1;
            break;
          }
          p++;
        }

        /* {{{ Is it a groupname? */
        if(isusername){
            ACD_INIT("Checking if group %s is valid.", s)

            if((gr = getgrnam(s)) == NULL){
                ACE_INIT("Groupname %s INVALID.", s)
                return 0;
            }

            gid = gr->gr_gid;
        } /* }}} */

        /* {{{ Otherwise its a UID: */
        else {
            gid = (gid_t)atoi(s);
            ACD_INIT("Checking if GID %d is valid.", gid)

            if((gr = getgrgid(gid)) == NULL){
                ACE_INIT("GID %d invalid.", gid)
                return 0;
            }
            gid = gr->gr_gid;
        } /* }}} */

    }  /* }}} */

    ACD_INIT("UID=%d, GID=%d.", uid, gid)

    /* {{{ Memory for stat buffer sb: */
    if((sb = XMALLOC(struct stat, 1)) == NULL){
        ACE_INIT("Mem err for statbuf: %s", strerror(errno))
        return 0;
    } /* }}} */

// Malloc'ed: sb

    /* {{{ Get the homedir, if defined: */

    if ((s = config_get_string("auth-cdb-homedir")) == NULL){
        ACD_INIT("homedir defined in config.")
        if((homedir = XMALLOC(char, strlen(s) + 1)) == NULL){
            ACE_INIT("Mem err for homedir, from config: ", strerror(errno))
            xfree(sb);
            return 0;
        }
        strcpy(homedir, s);

    } else {
        ACD_INIT("Using homedir from pwfile.")
        if((homedir = XMALLOC(char, strlen(pw->pw_dir)+1)) == NULL){
            ACE_INIT("Mem err for homedir, from pwfile: ", strerror(errno))
            return 0;
        }
        strcpy(homedir, pw->pw_dir);
    }

    if(stat(homedir, sb) < 0){
        ACE_INIT("homedir '%s', stat failed: %s", homedir, strerror(errno))
        xfree(sb);
        xfree(homedir);
        return 0;
    } /* }}} */


// Malloc'ed: sb, homedir

    /* {{{ See if userpass.cdb exists: */
    if ((s = config_get_string("auth-cdb-userfile")) == NULL){
        ACE_INIT("auth-cdb-userfile not defined")
        xfree(sb);
        xfree(homedir);
        return 0;
    }

    if(stat(s, sb) < 0){
        ACE_INIT("userfile.cdb '%s', stat failed: %s",
                             s, strerror(errno))
        xfree(sb);
        xfree(homedir);
        return 0;
    }

    if((userfile = XMALLOC(char, strlen(s) +1)) == NULL){
        ACE_INIT("Mem error for userfile: %s", strerror(errno))
        xfree(sb);
        xfree(homedir);
        return 0;
    }

    strcpy(userfile, s);
    ACD_INIT("Userfile CDB defined as: %s", userfile)
    /* }}} */

// Malloc'ed: sb, homedir, userfile

    /* {{{ See if spool.cdb exists: */
    /* No separate spool file defined */
    if ((s = config_get_string("auth-cdb-spoolfile")) != NULL){
        ACD_INIT("Separate spoolfile CDB defined")

        if(stat(s, sb) != 0){
            ACE_INIT("spoolfile.cdb '%s', stat failed: %s", strerror(errno))
            xfree(sb);
            xfree(userfile);
            xfree(homedir);
            return 0;
        }

        if((spoolfile = XMALLOC(char, strlen(s) +1)) == NULL){
            ACE_INIT("Mem error for spoolfile: %s", strerror(errno))
            xfree(sb);
            xfree(userfile);
            xfree(homedir);
            return 0;
        }

        strcpy(spoolfile, s);
        ACD_INIT("Separate spoolfile CDB: %s", spoolfile)
    } else {
        options |= O_COMBINED_SPOOL; /* split user/pass and spool CDB's */
        ACD_INIT("Userfile CDB contains spool data")
    }
    /* }}} */

// Malloc'ed: sb, homedir, userfile, spoofile

#ifdef WANBLIST
    /* {{{ Look for whitelists and blacklists if they're enabled. */
    if(options & O_ENABLE_ACL){
        /* {{{ Whitelist: */
        if((s = config_get_string("auth-cdb-acl-whitelist")) == NULL){
            ACE_INIT("No whitelist ACL CDB defined.")
            xfree(sb);
            xfree(homedir);
            xfree(userfile);
            xfree(spoolfile);
            return 0;
        }

        if(stat(s, sb) != 0){
            ACE_INIT("Whitelist CDB %s does not exist : %s",
                     acl_wl, strerror(errno));
            xfree(sb);
            xfree(homedir);
            xfree(userfile);
            xfree(spoolfile);
            return 0;
        }

        if((acl_wl = XMALLOC(char * strlen(s) +1)) == NULL){
            ACE_INIT("Mem error for acl_wl: %s", strerror(errno))
            xfree(sb);
            xfree(homedir);
            xfree(userfile);
            xfree(spoolfile);
            return 0;
        }

        strcpy(acl_wl, s);
        ACD_INIT("Whitelist CDB is: %s", acl_wl)
        /* }}} */

// Malloc'ed: sb, homedir, userfile, spoofile, acl_wl

        /* {{{ Blacklist: */
        if((s = config_get_string("auth-cdb-acl-blacklist")) == NULL){
            ACE_INIT("No blacklist ACL CDB defined.")
            xfree(sb);
            xfree(homedir);
            xfree(userfile);
            xfree(spoolfile);
            return 0;
        }

        if(stat(s, sb) != 0){
            ACE_INIT("Blacklist CDB %s does not exist : %s",
                      acl_bl, strerror(errno));
            xfree(sb);
            xfree(homedir);
            xfree(userfile);
            xfree(spoolfile);
            return 0;
        }

        if((acl_bl = XMALLOC(char, strlen(s) +1)) == NULL){
            ACE_INIT("Mem error for acl_bl: %s", strerror(errno))
            xfree(sb);
            xfree(homedir);
            xfree(userfile);
            xfree(spoolfile);
            return 0;
        }

        strcpy(acl_bl, s);
        ACD_INIT("Blacklist CDB is: %s", acl_bl)
        /* }}} */

// Malloc'ed: sb, homedir, userfile, spoofile, acl_wl, acl_bl
    }
    /* }}} */
#endif

    /* {{{ Get the bulletins dir, if defined: */
    if(options & O_ENABLE_BULLETINS){
        if ((s = config_get_string("auth-cdb-bulletins-directory")) == NULL){
            ACD_INIT("Bulletins enabled, but auth-cdb-bulletins-directory " \
                     "not defined. Disabling bulletins.");
            options ^= O_ENABLE_BULLETINS;
        } else {
            if(stat(s, sb) < 0){
                ACE_INIT("Bulletins dir '%s', stat failed: %s. Disabling",
                         s, strerror(errno));
                options ^= O_ENABLE_BULLETINS;
            } else {
                if((bulldir = XMALLOC(char, strlen(s) + 1)) == NULL){
                    ACE_INIT("Mem err for bulldir, from config: ", strerror(errno))
                    xfree(sb);
                    xfree(homedir);
                    xfree(userfile);
                    xfree(spoolfile);
                    return 0;
                }
                strcpy(bulldir, s);
                if(bulldir[strlen(bulldir)-1] == '/')
                    bulldir[strlen(bulldir)-1] = '\0';
                ACD_INIT("Bulletins dir=%s", bulldir)
            }
        }
    } /* }}} */

// Malloc'ed: sb, homedir, userfile, spoofile, bulldir #WANDBL{acl_wl, acl_bl}

    ACD_INIT("Run with UID=%d, GID=%d HOME=%s", uid, gid, homedir)
    xfree(sb);
    return 1;
} /* }}} */

/* {{{ authcontext auth_cdb_new_user_pass(user, local_part, domain, pass, srcip, serverhost) */
authcontext auth_cdb_new_user_pass(const char *user, const char *local_part, const char *domain, const char *pass, const char *srcip, const char *serverhost){
  return (authcontext)auth_cdb_authenticate((char *)user, local_part, domain, NULL, pass, srcip, serverhost);
} /* }}} */

/* {{{ authcontext auth_cdb_new_apop(user, local_part, domain, timestamp, digest, srcip, serverhost) */
authcontext auth_cdb_new_apop(const char *user, const char *local_part, const char *domain, const char *timestamp,
                              const unsigned char *digest, const char *srcip, const char *serverhost){
  return (authcontext)auth_cdb_authenticate((char *)user, local_part, domain, timestamp, digest, srcip, serverhost);
} /* }}} */

/* {{{ authcontext auth_cdb_authenticate(user, local_part, domain, timestamp, digest, srcip, serverhost)
 * This one function handles both PASS and APOP methods.
 */
authcontext auth_cdb_authenticate(char *user, const char *local_part, const char *domain, const char *timestamp, const unsigned char *digest, const char *srcip, const char *serverhost) {
    int ret; // for cdbget()
    char *p;
    char *key;
    char *buf;
    char *mailbox = NULL;
    char *dpass   = NULL;
    authcontext a = NULL;

    ACD_AUTH("user=%s, domain=%s, type=%", user, domain,
                       (timestamp == NULL ? "USER/PASS" : "APOP"));

    if((buf = XMALLOC(char, BUFLEN)) == NULL){
        ACE_AUTH("Mem error for CDB buf: %s", strerror(errno))
        return NULL;
    }

// Malloc'ed: buf

//    if((key = xmalloc(sizeof(char) * (strlen(user) + strlen(domain) + 2))) == NULL){
    if((key = XMALLOC(char, strlen(user) + 1)) == NULL){
        ACE_AUTH("Mem error for CDB key: %s", strerror(errno))
        xfree(buf);
        return NULL;
    }

    if(!(options & O_CASE_SENSITIVE)){
        p = user;
        while(*p != 0){
            if(isupper(*p)) *p = tolower(*p);
            p++;
        }
    }

//    sprintf(key, "%s@%s", user, domain);
    strcpy(key, user);

// Malloc'ed: buf, key

#ifdef USERNAMES_ARE_EMAILS
    /* {{{ Convert user+domain => user@domain */
    if((p = rindex(key, '@')) == NULL){
      ACD_AUTH("No @ symbol in username.")

      if(options & O_ALLOW_PLUSSIGN){
        if((p = rindex(key, '+')) != NULL){
            ACD_AUTH("Replacing plus-sign in username.")
            *p = '@';
        } else if((p = rindex(key, '%')) != NULL){
            ACD_AUTH("Replacing percentage sign in username.")
            *p = '@';
        }
      } else {
        ACE_AUTH("Username does not contain an @ symbol.")
        xfree(key);
        xfree(buf);
        return NULL;
      }
    } /* }}} */
#endif


#ifdef USE_WANDBLIST
/* {{{ If USE_WANDBLIST */
/* Note: The rejection based on BL entry instead of incorrect password can
 *       most likely be detected fairly easily based on measuring the response
 *       time. This doesn't help an attacker any because no attacker with any
 *       clue would keep connecting from the same IP repeatedly anyway.
 *       Besides we're trying to do as little and as quickly as possible so we
 *       can ditch the connection and free up resources.
 */
    if(options & O_ENABLE_ACL){
        if((ret = is_blacklisted(key, srcip)) < 1){
            xfree(buf);
            xfree(key);
            return NULL;
        }

        // Explicitly blocked - Oi, no!
        if(ret == 1){
            ACE_AUTH("%s from %s explicitly blacklisted.", key, srcip)
            xfree(buf);
            xfree(key);
            return NULL;
        }

        // Range blocking - so although the range is blacklisted, the individual IP
        // could be whitelisted.
        if(ret == 2){
            ACD_AUTH("%s from %s in blacklisted range. Checking for " \
                     "whitelisted entry.",user,srcip);

            if((ret = is_whitelisted(key, srcip)) < 1){
                ACE_AUTH("%s from %s in blacklisted range and not whitelisted",
                         user, srcip);
                xfree(buf);
                xfree(key);
                return NULL;
            }

            // Otherwise its whitelisted:
            if(ret == 1)
                ACD_AUTH("IP %s whitelisted.", srcip)
            else if(ret == 2)
                ACD_AUTH("IP %s in whitelisted range.", srcip)
        }
    } else {
        ACD_AUTH("ACL's compiled in, but disabled. Ignoring.")
    }
/* }}} */
#endif

    /* {{{ Get password from CDB: */
    if((ret = cdbget(userfile, key, buf, BUFLEN-1)) < 0){
        // Errors generated by cdbget(), don't add extra here.
        xfree(buf);
        xfree(key);
        return NULL;
    }

    if(ret == 0){
        ACE_AUTH("No %spassword data for %s in userfile %s",
                (options & O_COMBINED_SPOOL ? "spool-" : ""), key, userfile);
        xfree(buf);
        xfree(key);
        return NULL;
    } /* }}} */


// Malloc'ed: buf, key

    /* {{{ If O_COMBINED_SPOOL set, we're using mbox/spool/dir:password: */
    if(options & O_COMBINED_SPOOL){
        ACD_AUTH("Using combined spool, searching for password.")

        /* {{{ Look for : at end of spooldir */
        if((p = index(buf, ':')) == NULL){
            ACE_AUTH("Error end of spooldir/start of password not found")
            xfree(buf);
            xfree(key);
            return NULL;
         } /* }}} */

        *p++ = 0; // replace : with \0 so buf string ends there
                  // and move p onto point to start of password

        if((mailbox = XMALLOC(char, strlen(buf) + 1)) == NULL){
            ACE_AUTH("Mem error for spooldir: %s", strerror(errno))
            xfree(buf);
            xfree(key);
            return NULL;
        }

// Malloc'ed: buf, key, mailbox

        if((dpass = XMALLOC(char, strlen(p) + 1)) == NULL){
            ACE_AUTH("Mem error for password: %s", strerror(errno))
            xfree(buf);
            xfree(key);
            xfree(mailbox);
            return NULL;
        }

        strcpy(mailbox, buf); // : replaced with a \0, so ok
        strcpy(dpass, p); // : replaced with a \0, so ok

        ACD_AUTH("Combined spool: mbox=%s, dpass=%s", mailbox,dpass)
    } /* }}} */

// Malloc'ed: buf, key, {mailbox, dpass}

    /* {{{ Otherwise this is just the password: */
    else {
        if((dpass = XMALLOC(char, strlen(buf) + 1)) == NULL){
            ACE_AUTH("Mem error for password: %s", strerror(errno))
            xfree(buf);
            xfree(key);
            return NULL;
        }
        strcpy(dpass, buf); // : replaced with a \0, so ok
    } /* }}} */

// Malloc'ed: buf, key, {mailbox}, dpass
// Note: mailbox for USER/PASS found after valid authen to save resources

    /* {{{ Is this a USER/PASS Authentication? */
    if(timestamp == NULL){

      /* Try to determine password type: */
      char type[15] = "{plaintext}";
      if(strncmp(dpass, "$1$", 3) == 0)
        strcpy(type, "{crypt_md5}");
      else if(strlen(dpass) == 13)
        strcpy(type, "{crypt}");

      // NOTE: "digest" is password entered from POP3 connection in this case:
      //       Falls back to testing in plain text since someone could have a
      //       plaintext password that looks like an MD5 hash to be secure.
      if(!check_password(user, dpass, digest, type) &&
         !((options & O_PLAINTEXT_FALLBACK)
            && strcmp(type, "{plaintext}") != 0
            && check_password(user, dpass, digest, "{plaintext}")) ){
          ACE_AUTH("%s failed login with wrong password", user)
          xfree(buf);
          xfree(key);
          xfree(dpass);
          if(mailbox != NULL) xfree(mailbox);
          return NULL;
      }
    } /* }}} */

    /* {{{ Otherwise its an APOP authentication: */
    /* Stupid APOP requires {plaintext} at the start of a plaintext password
     * and since you can only use plaintext passwords it means we have to
     * append {plaintext} to the start of all of the password.
     * Why can't it just assume this?
     */
    else {
        char *tmppass;
        if((tmppass = XMALLOC(char, strlen(dpass) + 12)) == NULL){
            ACE_AUTH("Mem error for tmppass: %s", strerror(errno))
            xfree(buf);
            xfree(key);
            xfree(dpass);
            if(mailbox != NULL) xfree(mailbox);
            return NULL;
        }

// Malloc'ed: buf, key, {mailbox}, dpass, tmppass
        sprintf(tmppass, "{plaintext}%s", dpass);

        /* Check if APOP string is valid: */
        if(!check_password_apop(user, tmppass, timestamp, digest)){
            ACE_AUTH("%s failed login with wrong APOP password", user)
            xfree(buf);
            xfree(key);
            xfree(dpass);
            xfree(tmppass);
            if(mailbox != NULL) xfree(mailbox);
            return NULL;
        }
        xfree(tmppass);
// Malloc'ed: buf, key, {mailbox}, dpass
    } /* }}} */

    /* {{{ Blank dpass memory for a little bit more security */
    p = dpass;
    while(*p != '\0'){ *p = '\0'; p++; }
    xfree(dpass);
    /* }}} */

// Malloc'ed: buf, key, {mailbox}

    /* {{{ Now Check if need to get maildir: */
    if(!(options & O_COMBINED_SPOOL)){
        if((ret = cdbget(spoolfile, key, buf, BUFLEN-1)) < 0){
            xfree(buf);
            xfree(key);
            if(mailbox != NULL) xfree(mailbox);
            return NULL;
        }

        if(ret == 0){
            ACE_AUTH("%s not found in spoolfile %s", key, spoolfile)
            xfree(buf);
            xfree(key);
            if(mailbox != NULL) xfree(mailbox);
            return NULL;
        }

        if((mailbox = XMALLOC(char, strlen(buf)+1)) == NULL){
            ACE_AUTH("Mem error for spooldir: %s", strerror(errno))
            xfree(buf);
            xfree(key);
            if(mailbox != NULL) xfree(mailbox);
            return NULL;
        }
        strcpy(mailbox, buf); // : replaced with a \0, so ok
    }
    /* }}} */

    a = authcontext_new(uid, gid, "maildir", mailbox, homedir);

// Malloc'ed: buf, key, mailbox

    xfree(key);
    xfree(buf);
    xfree(mailbox);

    return a;
} /* }}} */

/*  {{{ void auth_cdb_onlogin(authcontext, srcip, serverhost)
 *  Successful login. Check for bulletins, quota reports, etc.
 */
void auth_cdb_onlogin(const authcontext A, const char *srcip, const char *serverhost){
#ifdef USE_BULLETINS
    DIR *bdh, *sysbdh;
    char *bfname;
    char *bdir, *sysbdir;
    time_t lastmod;
    struct dirent *dent, *sysdent;
    struct stat *sb;
    int _tbcount = 0;
#endif

    ACD_LOGIN("For %s from=%s", A->user, srcip)

#ifdef USE_LAST_LOGIN
    /* {{{ Last login stuff: */
    if(options & O_KEEP_LAST_LOGIN){
        if(update_last_login(A->mailbox, (char *)srcip) < 0){
            ACE_LOGIN("Updating last login in: %s", A->mailbox)
            return;
        } else {
            ACD_LOGIN("Last login updated")
        }
    }
    /* }}} */
#endif


#ifdef USE_BULLETINS
    if(!(options & O_ENABLE_BULLETINS)) return;

    /* {{{ determine bulletin directory: */
    if((bdir = XMALLOC(char, strlen(A->mailbox) + strlen(BULLETIN_DIR_NAME)+2)) == NULL){
        ACE_LOGIN("Mem error for bulletin dir: %s", strerror(errno))
        return;
    }
    sprintf(bdir, "%s/%s", A->mailbox, BULLETIN_DIR_NAME);
    /* }}} */

    /* {{{ Allocate memory for stat buffer so we can determine file types. */
    if((sb = XMALLOC(struct stat, 1)) == NULL){
        ACE_LOGIN("Mem error for statbuf: %s", strerror(errno))
        xfree(bdir);
        return;
    } /* }}} */

// Malloc'ed: sb

    /* {{{ Try to open bulletin directory: */
    if((bdh = opendir(bdir)) == NULL){
        // Don't error if dir doesn't exist,
        // might not subscribe to any bulletins
        if(errno != ENOENT)
            ACE_LOGIN("Opening bulletin dir: %s", strerror(errno))
#ifdef VERBOSE_DEBUG
        else
            ACD_LOGIN("No bulletin directory.")
#endif
        else
        xfree(sb);
        xfree(bdir);
        return;
    }
    ACD_LOGIN("Opened bulletin dir %s", bdir)
    /* }}} */

// Malloc'ed: sb, opendir: bdir

    /* {{{ Loop through dir entries looking for bulletin files: */
    while((dent = readdir(bdh)) != NULL){
        int _bcount = 0; // for logging purposes

        // Short-circuit as we know these are dirs:
        if(strcmp(dent->d_name, ".") == 0 || strcmp(dent->d_name, "..") == 0)
          continue;

        ACD_LOGIN("Found bulletin dir entry %s", dent->d_name)

        /* {{{ Create bdir filename and stat to see if its a file: */
        if((bfname = XMALLOC(char, strlen(bdir) + strlen(dent->d_name) + 2)) == NULL){
            ACE_LOGIN("Mem error for bulletin dir entry: %s", strerror(errno))
            break;
        }
        sprintf(bfname, "%s/%s", bdir, dent->d_name);


// Malloc'ed: sb, bfname, opendir: bdir

        /* Stat to see if its a file/dir: */
        if(stat(bfname, sb) < 0){
            ACE_LOGIN("Stat'ing '%s': %s", bfname, strerror(errno))
            xfree(bfname);
            continue;
        }

        if(!S_ISREG(sb->st_mode)){
            ACE_LOGIN("bulletins dir %s contains directories", bdir)
            xfree(bfname);
            continue;
        } /* }}} */

// Malloc'ed: sb, bfname, opendir: bdir

        // Found bulletin file, get date and look for bulletins in matching
        // dir with dates of equal or greater than this.
        lastmod = sb->st_mtime;
        ACD_LOGIN("Found bulletin file %s lmod=%d", bfname, lastmod)

        /* {{{ Get subdir of system bulletin dir: */
        if((sysbdir = XMALLOC(char, strlen(bulldir) + strlen(dent->d_name)+ 2)) == NULL){
            ACE_LOGIN("Mem error for bulletin dir: %s", strerror(errno))
            break;
        }
        sprintf(sysbdir, "%s/%s", bulldir, dent->d_name);
        ACD_LOGIN("Checking in sys bulletin dir %s", sysbdir)
        /* }}} */

        /* {{{ Try to open bulletin directory:
         * Don't error if sysdir doesn't exist, bulletins are far less
         * important than mail sent to a customer so they should be able
         * to access that even if our bulletins dir is screwed up.
         */
        if((sysbdh = opendir(sysbdir)) == NULL){
            ACE_LOGIN("Opening system bulletin dir %s: %s",
                      sysbdir, strerror(errno));
            // this will keep happening so skip remaining bulletins:
            break;
        }
        ACD_LOGIN("Looking for bulletins in: %s", sysbdir)
        /* }}} */

        /* {{{ Check through all bulletins in this subdir of bulldir
         * Bulletins are named by posting date, so we don't need to stat them
         */
        while((sysdent = readdir(sysbdh)) != NULL){
            if(strcmp(sysdent->d_name, ".") == 0 ||
               strcmp(sysdent->d_name, "..")== 0 ||
               atoi(sysdent->d_name) < lastmod)
                continue;

            ACD_LOGIN("Found new bulletin: %s", sysdent->d_name)

            // Okay, so we need to copy this file to the mailbox,
            // and update the timestamp on the bulletins dir.
            if(copybulletin(sysbdir, sysdent->d_name, A->mboxdrv, A->mailbox) == 0){
                ACD_LOGIN("Copied bulletin")
                _bcount++;
            } else
                ACE_LOGIN("Error copying bulletin")
        } /* }}} */
        closedir(sysbdh);

        // Copied all of this type of bulletin. Update timestamp on the file
        if(_bcount != 0){
            ACD_LOGIN("Copied %d %s bulletins. Updating timestamp.",
                                _bcount, dent->d_name);

            if(utimes(bfname, NULL) != 0)
                ACE_LOGIN("Updating timestamp on bulletin %s: %s",
                                    bfname, strerror(errno));
            _tbcount += _bcount;
        }
    } /* }}} */

    if(errno != 0 && dent != NULL){
        ACE_LOGIN("Reading from bulletin dir: %s (%d)",strerror(errno), errno);
    } else {
        ACD_LOGIN("Finished reading bulletins dir (read %d)", _tbcount)
        if(_tbcount != 0 && !config_get_bool("onlogin-child-wait")){
            ACE_LOGIN("Directive \"onlogin-child-wait\" not set! Child has " \
               "(almost certainly) already scanned maildir and so will not " \
               "see new messages until next time.", _tbcount);
        }
    }


    xfree(sb);
    xfree(bdir);
    closedir(bdh);
#endif /* of ifdef USE_BULLETINS */
    return;
} /* }}} */

// /* {{{ void auth_cdb_postfork(void) */
// void auth_cdb_postfork(void) {
//     ACD_PFORK("Nothing defined yet")
// } /* }}} of auth_cdb_postfork() */

/* {{{ void auth_cdb_close(void) */
void auth_cdb_close(void) {
    ACD_CLOSE("Nothing defined yet")
    if(homedir != NULL) xfree(homedir);
    if(userfile != NULL) xfree(userfile);
    if(spoolfile != NULL) xfree(spoolfile);
} /* of auth_cdb_close() }}} */

#ifdef WANDBLIST
/* {{{ int is_blacklisted(char *key, char *srcip) */
// Return < 0 == error
//        = 0 == No
//        = 1 == matched individual IP/hostname
//        = 2 == matched IP range or hostname pattern.
int is_blacklisted(char *key, char *srcip){
    char *p;
    if((ret = cdbget(blacklist, key, buf, )) < 0)
        return -1;

    p = buf;
    while(*p != NULL){
    }

    return 0; // No
} /* }}} */

/* {{{ int is_whitelisted(char *key, char *srcip) */
// Return < 0 == error
//        = 0 == No
//        = 1 == matched individual IP/hostname
//        = 2 == matched IP range or hostname pattern.
int is_whitelisted(char *key, char *srcip){
    if((ret = cdbget(whitelist, key, buf, BUFLEN-1)) < 0)
        return -1;
    return 0; // No
} /* }}} */
#endif

/* {{{ int cdbget(char *file, char *key, char *buf, unsigned int buflen) */
int cdbget(char *file, char *key, char *buf, unsigned int buflen){
  int fd;
  int r;
  unsigned int dlen;
  uint32 dpos;
  static struct cdb c;

  // Buffer not big enough, get lost.
  if(buflen < 2){
    ACE_KEY("Key buffer too small (<2)")
    return -1;
  }

  buf[buflen] = '\0';
  buflen = buflen - 1;  // we can copy at most this so we always end with NULL

  ACD_KEY("called cdbget(\"%s\", \"%s\", buf, %d)", file,key,buflen)

  fd = open(file, O_RDONLY);
  if(fd == -1){
    ACE_KEY("Opening CDB '%s': %s", file, strerror(errno))
    return -2;
  }

  cdb_init(&c, fd);
  // cdb_findstart(&c); // - Don't need this as using cdb_find()

  r = cdb_find(&c, key, strlen(key));
  if(r == -1){
    ACE_KEY("Reading CDB file %s: %s", file, strerror(errno))
    CLOSEIT(-3);
  }

  // Nothing found (because cdb_find() is cdb_findstart() then cdb_findnext()
  // so the nth value in cdb_findnext() is always 1 and thus if exactly n-1
  // records 1-1 = 0 so no records - smart Dr DJB :)
  if(r == 0){
    ACE_KEY("No records for '%s' in '%s'", key, file)
    CLOSEIT(0);
  }

  dpos = cdb_datapos(&c);
  if(dpos < 0){
    ACE_KEY("Getting data pos for '%s' in '%s': %s", key,file,strerror(errno));
    CLOSEIT(-4);
  }

  dlen = cdb_datalen(&c);
  if(dlen < 0){
    ACE_KEY("Getting data len for '%s' in '%s': %s", key,file, strerror(errno))
    CLOSEIT(-5);
  }

  // Length of data bigger than buffer length :(
  if(dlen > buflen){
    ACE_KEY("Returned data len for '%s' in '%s' > than buf (%d>%d)",
              key, file, dlen, buflen);
    CLOSEIT(-6);
  }

  r = cdb_read(&c, buf, dlen, dpos);
  ACD_KEY("Read dlen=%d, from dpos=%d", dlen, dpos)

  // Read error :(
  if(r < 0){
    ACE_KEY("Reading data for '%s' from '%s': %s", key, file, strerror(errno));
    CLOSEIT(-7);
  }

  buf[dlen] = '\0'; // NULL terminate the text in buffer
  ACD_KEY("found '%s'", buf)
  CLOSEIT(1);
} /* end of cdbget() }}} */

#ifdef USE_BULLETINS
/* {{{ int copybulletin(char *sysbdir, char *sysbname, char *mboxdrv, char *mailbox) */
int copybulletin(char *sysbdir, char *sysbname, char *mboxdrv, char *mailbox){
    struct stat *sb;
    char size[20];
    char *seq;
    char *sfile;
    char *dfile;
    char *lbuf;
    int ifh = -1;
    int ofh = -1;
    int bytec = 0;

    ACD_LOGIN("copybulletin(%s, %s, %s, %s)",
              sysbdir, sysbname, mboxdrv, mailbox);

    if(strcmp(mboxdrv, "maildir") != 0){
        ACE_LOGIN("copybulletin() does not support mailbox format: %s",mboxdrv);
        return -1;
    }

    /* {{{ Make full filename of bulletin: */
    if((sfile = XMALLOC(char, strlen(sysbdir) + strlen(sysbname) + 2)) == NULL){
        ACE_LOGIN("Mem error for sfile dir: %s", strerror(errno))
        return -1;
    }

    sprintf(sfile, "%s/%s", sysbdir, sysbname);
    ACD_LOGIN("Bulletin source filename: %s", sfile)
    /* }}} */

// Malloc'ed sfile

    /* {{{ Check that it is a file and get its size */
    if((sb = XMALLOC(struct stat, 1)) == NULL){
        ACE_LOGIN("Mem error for sfile stat buf dir: %s", strerror(errno));
        xfree(sfile);
        return -1;
    }

// Malloc'ed sfile, sb

    if(stat(sfile, sb) < 0){
        ACE_LOGIN("Stat'ing '%s': %s", sfile,  strerror(errno))
        xfree(sb);
        xfree(sfile);
        return -1;
    }

    if(!S_ISREG(sb->st_mode)){
        ACE_LOGIN("bulletin src %s is not a file", sfile)
        xfree(sfile);
        return -1;
    }

    // Get size into string format.
    snprintf(size, 19, "%ld", sb->st_size);
    ACD_LOGIN("Size Bulletin source: %s", size)
    /* }}} */

// Malloc'ed sfile, sb

    if((seq = config_get_string("maildir-size-string")) == NULL)
        seq = ",S=";

    /* {{{ Now we know the size and bull filename we can copy it: */
    if((dfile = XMALLOC(char, strlen(mailbox) + strlen(sysbname) + strlen(seq)+
                        strlen(size) + 6)) == NULL){
        ACE_LOGIN("Mem error for dfile dir: %s", strerror(errno))
        xfree(sb);
        xfree(sfile);
        return -1;
    }

    xfree(sb);

    sprintf(dfile, "%s/new/%s%s%s", mailbox, sysbname, seq, size);
    ACD_LOGIN("Bulletin dest filename: %s", dfile)
    /* }}} */

// Malloc'ed sfile, dfile

    if((lbuf = XMALLOC(char, BUFLEN)) == NULL){
        ACE_LOGIN("Mem error for lbuf dir: %s", strerror(errno))
        xfree(dfile);
        xfree(sfile);
        return -1;
    }

// Malloc'ed sfile, dfile, lbuf

    // Okay, now to copy the files:
    if((ifh = open(sfile, O_RDONLY)) < 0){
        ACE_LOGIN("Opening sfile %s: %s", sfile, strerror(errno))
        xfree(dfile);
        xfree(sfile);
        return -1;
    }

    if((ofh = open(dfile, O_WRONLY|O_CREAT)) < 0){
        ACE_LOGIN("Opening dfile %s: %s", dfile, strerror(errno))
        xfree(dfile);
        xfree(sfile);
        return -1;
    }

// TODO: Soemthing in here for inserting customer name :p

    ACD_LOGIN("Copying source bulletin %s to dest file %s", sfile, dfile)
    while((bytec = read(ifh, lbuf, BUFLEN-1)) > 0){
        write(ofh, lbuf, bytec);
    }

    if(bytec < 0){
        ACE_LOGIN("Copying bulletin to %s: %s", dfile, strerror(errno))
        unlink(dfile);
    } else {
        ACD_LOGIN("Successful copy %s=>%s", sfile, dfile)
        if(fchown(ofh, uid, gid) < 0)
            ACE_LOGIN("Chown'ing bulletin %s to %d:%d: %s",
                      dfile, uid, gid, strerror(errno));

        // Must set this or user won't be able to delete it.
        if(fchmod(ofh, BULPERMS) < 0)
            ACE_LOGIN("Chmod'ing bulletin %s to %o: %s",
                      dfile, BULPERMS, strerror(errno));
    }

    close(ifh);
    close(ofh);

    xfree(dfile);
    xfree(sfile);
    xfree(lbuf);

    // Still needed to close + free, etc. so check again here if was error.
    if(bytec < 0) return -1;

    return 0;
} /* }}} */
#endif

#ifdef USE_LAST_LOGIN
/* {{{ int update_last_login(char *mbox, char *srcip) */
int update_last_login(char *mbox, char *srcip){
    int ofh;
    char *p;
    char *llogin, *actual_llogin;
    char *out;

    if(!(options & O_KEEP_LAST_LOGIN)) return 0;

    ACD_UPDLL("Recording last login info")

    if((llogin = XMALLOC(char, strlen(mbox) + strlen(LAST_LOGIN_FILE) + 2 + 4)) == NULL){
        ACE_UPDLL("Mem error for tmp lastlogin: %s", strerror(errno))
        return -1;
    }

// Malloc'ed: llogin
    sprintf(llogin, "%s/%s.tmp", mbox, LAST_LOGIN_FILE);

    if((ofh = open(llogin, O_WRONLY|O_CREAT|O_TRUNC)) < 0){
        ACE_UPDLL("Opening tmp lastlogin file %s: %s", llogin,strerror(errno))
        xfree(llogin);
        return -2;
    }

    if(fchown(ofh, uid, gid) < 0)
        ACE_UPDLL("Chown'ing last login %s to %d:%d: %s",
                  llogin, uid, gid, strerror(errno));

    // Must set this or user won't be able to delete it.
    if(fchmod(ofh, LLPERMS) < 0)
        ACE_UPDLL("Chmod'ing last login %s to %o: %s",
                            llogin, LLPERMS, strerror(errno));

    if((out = XMALLOC(char, strlen(srcip) + 2)) == NULL){
        ACE_UPDLL("Mem error for lastlogin out:%s", strerror(errno))
        return -3;
    }

// Malloc'ed: llogin, out

    sprintf(out, "%s\n", srcip);
    p = out;
    while(*p != 0){
        int wrote = write(ofh, p, strlen(p));
        if(wrote < 0){
            ACE_UPDLL("Writing lastlogin info %s to %s: %s",
                                 srcip, llogin, strerror(errno));
            xfree(out);
            xfree(llogin);
            return -4;
        }
        p += wrote;
        ACD_UPDLL("Have %d bytes remaining", strlen(p))
    }
    close(ofh);
    xfree(out);

// Malloc'ed: llogin

    if((actual_llogin = XMALLOC(char, strlen(mbox) + strlen(LAST_LOGIN_FILE) + 2)) == NULL){
        ACE_UPDLL("Mem error for actual_lastlogin: %s", strerror(errno))
        xfree(llogin);
        return -5;
    }

// Malloc'ed: llogin, actual_llogin
    sprintf(actual_llogin, "%s/%s", mbox, LAST_LOGIN_FILE);
    ACD_UPDLL("renaming %s => %s", llogin, actual_llogin)

    if(rename(llogin, actual_llogin) < 0){
        ACE_UPDLL("Renaming %s => %s: %s",
                  llogin, actual_llogin, strerror(errno));
        xfree(llogin);
        xfree(actual_llogin);
        return -6;
    }

    xfree(llogin);
    xfree(actual_llogin);

    ACD_UPDLL("Wrote lastlogin info")
    return 0;
} /* }}} */
#endif

#endif /* AUTH_CDB */


