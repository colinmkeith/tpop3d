/*
 * config.h:
 * config file parsing
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

#ifndef __CONFIG_H_ /* include guard */
#define __CONFIG_H_

#include "stringmap.h"

stringmap read_config_file(const char *f);
int is_cfgdirective_valid(const char *s);
int config_get_int(const char *directive, int *value);
int config_get_float(const char *directive, float *value);
char *config_get_string(const char *directive);
int config_get_bool(const char *directive);

#endif /* __CONFIG_H_ */
