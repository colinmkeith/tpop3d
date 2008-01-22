/*
 * pidfile.c:
 * functions for creating and removing PID files
 *
 * Copyright (c) 2001 Mark Longair.
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

static const char copyright[] = "$Copyright: (c) 2001 Chris Lightfoot. $";
static const char rcsid[] = "$Id$";

#ifdef HAVE_CONFIG_H
#include "configuration.h"
#endif /* HAVE_CONFIG_H */

#include "pidfile.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

/* write_pid_file:
 * Writes the current process ID to `filename'.  Returns
 * pid_file_success on success, pid_file_existence if the file already
 * exists, and pid_file_error in the case of any other error.
 */
pid_file_result
write_pid_file(const char * filename)
{
    int fd;
    pid_t pid;
    char line[32];

    fd = open(filename,
              O_WRONLY|O_CREAT|O_EXCL|O_TRUNC,
              S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);

    if(fd == -1) {
        if(errno == EEXIST)
            return pid_file_existence;
        else
            return pid_file_error;
    }

    pid = getpid();

    snprintf(line, 32, "%lu", (unsigned long)pid);

    if (strlen(line) > write(fd, line, strlen(line)))
        return pid_file_error;

    if (close(fd) == -1)
        return pid_file_error;

    return pid_file_success;
}

/* read_pid_file:
 * Opens the PID file at `filename' and stores the PID in it at `pid'.
 * Returns pid_file_success on success (i.e. PID read successfully),
 * pid_file_existence if the file does not exist, or pid_file_error
 * for any other error.
 */
pid_file_result
read_pid_file(const char * filename, pid_t * pid)
{
    char line[32], *endptr;
    int fd;
    pid_t parsed;
    ssize_t available;

    fd = open( filename, O_RDONLY );

    if (fd == -1) {

        if (errno == ENOENT )
            return pid_file_existence;
        else
            return pid_file_error;

    }
   
    available = read( fd, line, 32 );
    if (available >= 31) {
        close(fd);
        return pid_file_error;
    }
    
    line[available] = '\0';

    parsed = (pid_t)strtol(line, &endptr, 10);

    if((*line == '\0') || (*endptr != '\0')) {
        return pid_file_error;
    }

    if (close(fd) == -1)
        return pid_file_error;

    *pid = parsed;

    return pid_file_success;
}

/* remove_pid_file:
 * Returns pid_file_success on success, pid_file_existence if the file
 * does not exist, or pid_file_error for any other error.
 */
pid_file_result
remove_pid_file(const char * filename)
{
    int result = unlink( filename );

    if (result == 0)
        return pid_file_success;
    else {
        if (errno == ENOENT)
            return pid_file_existence;
        else
            return pid_file_error;
    }
}
