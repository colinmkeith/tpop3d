/*
 * password.c:
 * Verify a submitted password against the real one, subject to interpretation
 * of an optional {scheme} prefix.
 *
 * Collects various crypting routines in one place.
 *
 * Copyright (c) 2001 Chris Lightfoot.
 * Refactoring (c) 2003 Paul Makepeace.
 * All rights reserved.
 *
 */


#ifdef HAVE_CONFIG_H
#include "configuration.h"
#endif /* HAVE_CONFIG_H */

#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif

#ifdef AUTH_MYSQL
#include <mysql.h>
#endif

#include <stdio.h>
#include <string.h>
#include <syslog.h>

#include "md5.h"
#include "util.h"

static const char rcsid[] = "$Id$";

/* 
 * MD5 crypt(3) routines. This is here so that you can migrate passwords from
 * the modern /etc/shadow crypt_md5 format used (optionally) by recent
 * Linux-PAM distributions. This code was taken from Linux-PAM 0.75.
 *
 * (Note that on most Linux systems this won't be necessary, since the system
 * crypt(3) function is `smart' in the sense that it looks for a constant
 * string `$1$' at the beginning of the password hash, and if that string is
 * present, uses crypt_md5 instead of traditional crypt. However, I include
 * this function in the interests of portability and future compatibility.)
 *
 * Original author's notice:
 * 
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <phk@login.dknet.dk> wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.   Poul-Henning Kamp
 */

static unsigned char itoa64[] = /* 0 ... 63 => ascii - 64 */
        "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/* to64 BUFFER VALUE NUM
 * Write NUM base64 characters of VALUE into BUFFER. */
static void to64(char *s, unsigned long v, int n)
{
    while (--n >= 0) {
        *s++ = itoa64[v&0x3f];
        v >>= 6;
    }
}

/* crypt_md5 PASSWORD SALT
 * Poul-Henning Kamp's crypt(3)-alike using MD5. */
static char *crypt_md5(const char *pw, const char *salt)
{
    const char *magic = "$1$";
    /* This string is magic for this algorithm.  Having
     * it this way, we can get get better later on */
    static char passwd[120], *p;
    static const char *sp,*ep;
    unsigned char   final[16];
    int sl,pl,i,j;
    md5_ctx ctx,ctx1;
    unsigned long l;

    /* Refine the Salt first */
    sp = salt;

    /* If it starts with the magic string, then skip that */
    if(!strncmp(sp,magic,strlen(magic)))
        sp += strlen(magic);

    /* It stops at the first '$', max 8 chars */
    for(ep=sp;*ep && *ep != '$' && ep < (sp+8);ep++)
        continue;

    /* get the length of the true salt */
    sl = ep - sp;

    MD5Init(&ctx);

    /* The password first, since that is what is most unknown */
    MD5Update(&ctx,(unsigned char *)pw,strlen(pw));

    /* Then our magic string */
    MD5Update(&ctx,(unsigned char *)magic,strlen(magic));

    /* Then the raw salt */
    MD5Update(&ctx,(unsigned char *)sp,sl);

    /* Then just as many characters of the MD5(pw,salt,pw) */
    MD5Init(&ctx1);
    MD5Update(&ctx1,(unsigned char *)pw,strlen(pw));
    MD5Update(&ctx1,(unsigned char *)sp,sl);
    MD5Update(&ctx1,(unsigned char *)pw,strlen(pw));
    MD5Final(final,&ctx1);
    for(pl = strlen(pw); pl > 0; pl -= 16)
        MD5Update(&ctx,(unsigned char *)final,pl>16 ? 16 : pl);

    /* Don't leave anything around in vm they could use. */
    memset(final,0,sizeof final);

    /* Then something really weird... */
    for (j=0,i = strlen(pw); i ; i >>= 1)
        if(i&1)
            MD5Update(&ctx, (unsigned char *)final+j, 1);
        else
            MD5Update(&ctx, (unsigned char *)pw+j, 1);

    /* Now make the output string */
    strcpy(passwd,magic);
    strncat(passwd,sp,sl);
    strcat(passwd,"$");

    MD5Final(final,&ctx);

    /*
     * and now, just to make sure things don't run too fast
     * On a 60 Mhz Pentium this takes 34 msec, so you would
     * need 30 seconds to build a 1000 entry dictionary...
     */
    for(i=0;i<1000;i++) {
        MD5Init(&ctx1);
        if(i & 1)
            MD5Update(&ctx1,(unsigned char *)pw,strlen(pw));
        else
            MD5Update(&ctx1,(unsigned char *)final,16);

        if(i % 3)
            MD5Update(&ctx1,(unsigned char *)sp,sl);

        if(i % 7)
            MD5Update(&ctx1,(unsigned char *)pw,strlen(pw));

        if(i & 1)
            MD5Update(&ctx1,(unsigned char *)final,16);
        else
            MD5Update(&ctx1,(unsigned char *)pw,strlen(pw));
        MD5Final(final,&ctx1);
    }

    p = passwd + strlen(passwd);

    l = (final[ 0]<<16) | (final[ 6]<<8) | final[12]; to64(p,l,4); p += 4;
    l = (final[ 1]<<16) | (final[ 7]<<8) | final[13]; to64(p,l,4); p += 4;
    l = (final[ 2]<<16) | (final[ 8]<<8) | final[14]; to64(p,l,4); p += 4;
    l = (final[ 3]<<16) | (final[ 9]<<8) | final[15]; to64(p,l,4); p += 4;
    l = (final[ 4]<<16) | (final[10]<<8) | final[ 5]; to64(p,l,4); p += 4;
    l =                    final[11]                ; to64(p,l,2); p += 2;
    *p = '\0';

    /* Don't leave anything around in vm they could use. */
    memset(final,0,sizeof final);

    return passwd;
}

/* MD5 crypt(3) routines end. */


/* 
 * MySQL PASSWORD() routines. This is here so that you can use the MySQL
 * proprietary password-hashing routine with tpop3d. The code is inserted here
 * to avoid having to do an explicit query to get the MySQL password hash.
 * Observe that this is not completely safe, since the machine on which the
 * MySQL server is running may use a different character set to this machine.
 * However, it is probably not worth worrying about this in reality.
 *
 * In fact, these functions will probably be available in libmysqlclient, but
 * that doesn't appear to be documented, so better safe than sorry.
 *
 * We make these functions available whether or not MySQL support is
 * available, since they don't depend on MySQL and it's possible that somebody
 * might want to migrate passwords from a MySQL database to some other system.
 *
 * This code is taken from the MySQL distribution. The original license for
 * the code in sql/password.c states:
 *
 * Copyright Abandoned 1996 TCX DataKonsult AB & Monty Program KB & Detron HB
 * This file is public domain and comes with NO WARRANTY of any kind
 */

/* mysql_hash_password RESULT PASSWORD
 * Basic MySQL password-hashing routine. */
static void mysql_hash_password(unsigned long *result, const char *password) {
    register unsigned long nr=1345345333L, add=7, nr2=0x12345671L;
    unsigned long tmp;
    for (; *password; password++) {
        if (*password == ' ' || *password == '\t')
            continue;           /* skip space in password */
        tmp  = (unsigned long) (unsigned char) *password;
        nr  ^= (((nr & 63) + add) * tmp) + (nr << 8);
        nr2 += (nr2 << 8) ^ nr;
        add += tmp;
    }
    result[0] =  nr & (((unsigned long) 1L << 31) -1L); /* Don't use sign bit (str2int) */;
    result[1] = nr2 & (((unsigned long) 1L << 31) -1L);
    return;
}

/* mysql_make_scrambled_password RESULT PASSWORD
 * MySQL function to form a password hash and turn it into a string. */
static void mysql_make_scrambled_password(char *to, const char *password) {
    unsigned long hash_res[2];
    mysql_hash_password(hash_res, password);
    sprintf(to, "%08lx%08lx", hash_res[0], hash_res[1]);
}

/* MySQL PASSWORD() routines end. */

/* check_password USER HASH PASSWORD SCHEME
 * Determine whether the given PASSWORD for the named USER matches the known
 * password HASH. If there is no scheme specified in {} at the beginning of
 * HASH, assume that it is SCHEME, which must be specified with the enclosing
 * {}. Returns 1 if PASSWORD matches HASH, or 0 otherwise. */
int check_password(const char *who, const char *pwhash, const char *pass, const char *default_crypt_scheme) {
    const char *realhash;

    if (*pwhash == '{' && (realhash = strchr(pwhash + 1, '}')))
        ++realhash;
    else
        realhash = pwhash;

    /* Helper macro to detect schemes. */
#   define IS_SCHEME(hash, scheme, def)                                 \
        ((*hash == '{' && strncmp(hash, scheme, strlen(scheme)) == 0)   \
         || strcmp(scheme, def) == 0)
    
    if (IS_SCHEME(pwhash, "{crypt}", default_crypt_scheme)) {
        /* Password hashed by system crypt function. */
        return strcmp(crypt(pass, realhash), realhash) == 0;
    } else if (IS_SCHEME(pwhash, "{crypt_md5}", default_crypt_scheme)) {
        /* Password hashed by crypt_md5. */
        return strcmp(crypt_md5(pass, realhash), realhash) == 0;
    } else if (IS_SCHEME(pwhash, "{plaintext}", default_crypt_scheme)) {
        /* Plain text password, as used for APOP. */
        return strcmp(pass, realhash) == 0;
    } else if (IS_SCHEME(pwhash, "{mysql}", default_crypt_scheme)) {
        /* MySQL PASSWORD() type password hash. */
        char hash[17] = {0};
        int n;
        mysql_make_scrambled_password(hash, pass);
        /* The MySQL password format changed, and we should accept either a 16-
         * or 8-character long hash. */
        switch (n = strlen(pwhash)) {
            case 8:
                return strncmp(hash, realhash, 8) == 0;

            case 16:
                return strcmp(hash, realhash) == 0;

            default:
                log_print(LOG_ERR, _("password: %s has password type mysql, but hash is of incorrect length %d (expecting 8 or 16)"), who, n);
                return 0;
        }
    } else if (IS_SCHEME(pwhash, "{md5}", default_crypt_scheme)) {
        /* Straight MD5 password. But this might be either in hex or base64
         * encoding. */
        if (strlen(realhash) == 32) {
            /* Hex. */
            return strcasecmp(realhash, md5_digest_str(pass, strlen(pass), 0));
        } else if (strlen(pwhash) == 24) {
            /* Base 64. */
            return strcmp(realhash, md5_digest_str(pass, strlen(pass), 1)) == 0;
        } else
            /* Doesn't make sense. */
            log_print(LOG_ERR, _("password: %s has password type md5, but hash is of incorrect length"), who);
            return 0;
    } else {
        /* Unknown format. */
        log_print(LOG_ERR, _("password: %s has unknown password format `%.*s'"), who, strcspn(pwhash, "}"), pwhash);
        return 0;
    }
}

/* check_password_apop USER HASH TIMESTAMP DIGEST
 * Determine whether the MD5 DIGEST supplied by USER matches the given
 * password HASH and known TIMESTAMP. Returns 1 if the user has supplied a
 * correct DIGEST, and 0 otherwise. Requires that HASH is of type
 * {plaintext}. */
int check_password_apop(const char *who, const char *pwhash, const char *timestamp, const unsigned char *digest) {
    md5_ctx ctx;
    unsigned char this_digest[16];

    /* Verify that this user has a plaintext password. */
    if (strncmp(pwhash, "{plaintext}", 11) != 0) {
        log_print(LOG_WARNING, _("password: attempted APOP login by %s, who does not have a plaintext password"), who);
        return 0;
    }
    pwhash += 11;

    /* Calculate our idea of the digest */
    MD5Init(&ctx);
    MD5Update(&ctx, (unsigned char*)timestamp, strlen(timestamp));
    MD5Update(&ctx, (unsigned char*)pwhash,    strlen(pwhash));
    MD5Final(this_digest, &ctx);

    return memcmp(this_digest, digest, 16) == 0;
}
