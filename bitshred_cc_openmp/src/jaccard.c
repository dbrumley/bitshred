#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "jaccard.h"
#include "bs_common.h"

extern unsigned int limit;

inline float jaccard_vdb(bitshred_t *vdb_a, bitshred_t *vdb_b, int nbits_a, int nbits_b) {
    unsigned int bitvector_union = 0; 
    unsigned int bitvector_intersection = 0;
    int i;

    // bitwise AND between two vectors
    for(i=0; i<FP_SIZE/4; i++) {
        bitvector_intersection += bitcount(((unsigned int*)vdb_a->bit_vector)[i] & ((unsigned int *)vdb_b->bit_vector)[i]);
    }

    /* Without Containment */
    bitvector_union = nbits_a + nbits_b - bitvector_intersection;

    /* With Containment */
    /*
    if(nbits_a==nbits_b) {
        bitvector_union = nbits_a + nbits_b - bitvector_intersection;
    }
    else if(nbits_a>nbits_b) {
        bitvector_union = nbits_b;
    }
    else {
        bitvector_union = nbits_a;
    }
    */

    return (float)bitvector_intersection / bitvector_union;
}
