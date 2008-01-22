/*
 * pidfile.h:
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
