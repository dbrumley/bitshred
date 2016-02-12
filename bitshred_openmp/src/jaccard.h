#ifndef __JACCARD_H__
#define __JACCARD_H__

#include <stdio.h>
#include "vdb.h"

#define JACCARD_THRESHOLD     0.7

extern double threshold; 

/* jaccard.c */
inline float jaccard_vdb(bitshred_t *vdb_a, bitshred_t *vdb_b, int nbits_a, int nbits_b);

#endif
