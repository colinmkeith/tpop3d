/*
 * locks.h:
 * Various means of locking files.
 *
 * Copyright (c) 2001 Chris Lightfoot. All rights reserved.
 *
 * $Id$
 *
 */

#ifndef __LOCKS_H_ /* include guard */
#define __LOCKS_H_

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

#endif /* __LOCKS_H_ */
