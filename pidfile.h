/*
 * pidfile.h:
 * functions for creating and removing PID files
 *
 * Copyright (c) 2001 Mark Longair. All rights reserved.
 *
 * $Id$
 *
 */

#ifndef PIDFILE__H_ /* include guard */
#define PIDFILE__H_

#include <sys/types.h>
#include <unistd.h>

typedef enum pid_file_result {

    pid_file_success,
    pid_file_existence,
    pid_file_error

} pid_file_result;

pid_file_result
write_pid_file (const char * filename);

pid_file_result
read_pid_file(const char * filename, pid_t * pid);

pid_file_result
remove_pid_file(const char * filename);

#endif
