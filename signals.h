/*
 * signals.h:
 * Signal handlers for tpop3d.
 *
 * Copyright (c) 2001 Chris Lightfoot. All rights reserved.
 *
 * $Id$
 *
 */

#ifndef __SIGNALS_H_ /* include guard */
#define __SIGNALS_H_

/* signals.c */
void set_signals(void);
void terminate_signal_handler(const int i);
void die_signal_handler(const int i);
void child_signal_handler(const int i);
void restart_signal_handler(const int i);

#endif /* __SIGNALS_H_ */
