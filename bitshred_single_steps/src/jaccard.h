#include <stdio.h>
#include "vdb.h"

#define JACCARD_THRESHOLD     0.6

extern double threshold; 

/* jaccard.c */
double jaccard_vdb(bitshred_t *vdb_a, bitshred_t *vdb_b);
