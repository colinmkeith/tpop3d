/*
 * buffer.h:
 * Circular buffers.
 *
 * Copyright (c) 2002 Chris Lightfoot. All rights reserved.
 * Email: chris@ex-parrot.com; WWW: http://www.ex-parrot.com/~chris/
 *
 * $Id$
 *
 */

#ifndef __BUFFER_H_ /* include guard */
#define __BUFFER_H_

typedef struct _buffer {
    size_t len;
    char *buf;
    off_t put, get;
} *buffer;

/* buffer_available BUFFER
 * Return the number of bytes of data available to consume from BUFFER. This
 * is a macro which may evaluate BUFFER more than once. */
#define buffer_available(B) (((B)->put + (B)->len - (B)->get) % (B)->len)

/* buffer.c */
buffer buffer_new(const size_t len);
void buffer_delete(buffer B);
char *buffer_get_consume_ptr(buffer B, size_t *slen);
void buffer_consume_bytes(buffer B, const size_t num);
char *buffer_consume_all(buffer B, char *str, size_t *slen);
char *buffer_consume_to_mark(buffer B, const char *mark, const size_t mlen, char *str, size_t *slen);
void buffer_expand(buffer B, const size_t num);
void buffer_push_data(buffer B, const char *data, const size_t dlen);
char *buffer_get_push_ptr(buffer B, size_t *len);
void buffer_push_bytes(buffer B, const size_t num);

#endif /* __BUFFER_H_ */
