/*
 * config.h:
 * config file parsing
 *
 * Copyright (c) 2001 Chris Lightfoot. All rights reserved.
 *
 * $Id$
 *
 */

#ifndef __CONFIG_H_ /* include guard */
#define __CONFIG_H_

#include "stringmap.h"

stringmap read_config_file(const char *f);
int is_cfgdirective_valid(const char *s);

#endif /* __CONFIG_H_ */
