/*
 * mailspool.h: Berkeley mailspool handling
 *
 * Copyright (c) 2000 Chris Lightfoot. All rights reserved.
 *
 * $Id$
 *
 * $Log$
 * Revision 1.1  2000/10/02 18:21:25  chris
 * Initial revision
 *
 *
 */

#ifndef __MAILSPOOL_H_ /* include guard */
#define __MAILSPOOL_H_

#include <stdlib.h>
#include <sys/stat.h>

#include "connection.h"
#include "vector.h"

typedef struct _indexpoint {
    size_t offset, length, msglength;
    char deleted;
    unsigned char hash[16];
} *indexpoint;

typedef struct _mailspool {
    char *name;
    int fd;
    char isempty;
    struct stat st;
    vector index;
    int numdeleted;
} *mailspool;

mailspool mailspool_new_from_file(const char *filename);
void      mailspool_delete(mailspool m);

vector    mailspool_build_index(mailspool m);

int       mailspool_send_message(mailspool m, int sck, const int i, int n);

indexpoint indexpoint_new(const size_t offset, const size_t length, const size_t msglength, const void* data);

/* How long we wait between trying to lock the mailspool */
#define MAILSPOOL_LOCK_WAIT           2
/* How many times we try */
#define MAILSPOOL_LOCK_TRIES          4

#endif /* __MAILSPOOL_H_ */
