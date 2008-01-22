/*
 * locks.h:
 * Various means of locking files.
 *
 * Copyright (c) 2001 Chris Lightfoot.
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

#ifndef __LOCKS_H_ /* include guard */
#define __LOCKS_H_

#ifdef HAVE_CONFIG_H
#include "configuration.h"
#endif /* HAVE_CONFIG.H */

#ifdef MBOX_BSD

#if !defined(WITH_FCNTL_LOCKING) && !defined(WITH_FLOCK_LOCKING) && !defined(WITH_DOTFILE_LOCKING)
#   warning "No locking scheme defined; using dotfiles and flock(2)."
#   define WITH_FCNTL_LOCKING
#   define WITH_DOTFILE_LOCKING
#endif

#ifdef WITH_FCNTL_LOCKING
int fcntl_lock(int);
int fcntl_unlock(int);
#endif

#if defined(WITH_FLOCK_LOCKING) || (defined(WITH_CCLIENT_LOCKING) && !defined(CCLIENT_USES_FCNTL))
int flock_lock(int);
int flock_unlock(int);
#endif

#ifdef WITH_DOTFILE_LOCKING
int dotfile_lock(const char*);
int dotfile_unlock(const char *);
#endif

#ifdef WITH_CCLIENT_LOCKING
int cclient_steal_lock(int);
#endif

#endif /* MBOX_BSD */

#endif /* __LOCKS_H_ */
