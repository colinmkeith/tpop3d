/* GLOBAL.H - RSAREF types and constants
 */

#ifndef GLOBAL_H_
#define GLOBAL_H_

#include <limits.h>

/* POINTER defines a generic pointer type */
typedef unsigned char *POINTER;

/* UINT2 defines a two byte word */
typedef unsigned short int UINT2;

/* UINT4 defines a four byte word */
#if INT_MAX>32767L
typedef unsigned int UINT4;
#else
typedef unsigned long int UINT4;
#endif

#define PROTO_LIST(list) list

#endif
