#ifndef __UNPACK_H__
#define __UNPACK_H__

#include "bs_types.h"
#include "pe.h"

#define NOT_PACKED 0 
#define UNPACK_SUCCESS 1
#define PACKED_BUT_FAIL 2

int unpack(const char *file);


#endif
