#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "jaccard.h"
#include "bs_common.h"

/* measure the jaccard similarity */
double jaccard_vdb(bitshred_t *vdb_a, bitshred_t *vdb_b) {
    unsigned int bitvector_union = 0; 
    unsigned int bitvector_intersection = 0;
    unsigned int bitwise_and;
    int i;

    /* bitwise-AND between two bit-vectors */
    for(i=0; i<FP_SIZE/4; i++) {
        bitwise_and = ((unsigned int *)vdb_a->bit_vector)[i] & ((unsigned int *)vdb_b->bit_vector)[i];
        if (bitwise_and) 
            bitvector_intersection += bitcount(bitwise_and);
    }

    /* resemblance */
    bitvector_union = vdb_a->nbits + vdb_b->nbits - bitvector_intersection;


    /* containment */
    /*
    if(vdb_a->nbits>vdb_b->nbits) {
        bitvector_union = vdb_b->nbits;
    }
    else {
        bitvector_union = vdb_a->nbits;
    }
    */


    /* "harmony" = resemblance + containment */
    /*
    if(vdb_a->nbits==vdb_b->nbits) {
        bitvector_union = vdb_a->nbits+vdb_b->nbits-bitvector_intersection;
    }
    else if(vdb_a->nbits>vdb_b->nbits) {
        bitvector_union = vdb_b->nbits;
    }
    else {
        bitvector_union = vdb_a->nbits;
    }
    */

    return (float)bitvector_intersection / bitvector_union;
}
