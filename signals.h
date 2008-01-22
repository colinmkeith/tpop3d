/*
 * signals.h:
 * Signal handlers for tpop3d.
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

#ifndef __SIGNALS_H_ /* include guard */
#define __SIGNALS_H_

/* signals.c */
void set_signals(void);
void terminate_signal_handler(const int i);
void die_signal_handler(const int i);
void child_signal_handler(const int i);
void restart_signal_handler(const int i);

#endif /* __SIGNALS_H_ */
