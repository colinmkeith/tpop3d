/*
 * config.h: config file parsing
 *
 * Copyright (c) 2000 Chris Lightfoot. All rights reserved.
 *
 * $Id$
 *
 * $Log$
 * Revision 1.1  2000/10/02 18:20:19  chris
 * Initial revision
 *
 *
 */

#ifndef __CONFIG_H_ /* include guard */
#define __CONFIG_H_

#include "stringmap.h"

stringmap read_config_file(const char *f);

#endif /* __CONFIG_H_ */
