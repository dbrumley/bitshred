#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include "bs_common.h"

int debug_flag = 0;
extern unsigned int shredsize;

void bs_msg(const char *str, ...) {
    va_list args;
    char buff[BUFSIZ];
    va_start(args, str);
    vsnprintf(buff, sizeof(buff), str, args);
    buff[sizeof(buff)-1] = '\0';
    fputs(buff, stdout);
    //fflush(stdout);
    va_end(args);
}

void bs_verbosemsg(const char *str, ...) {
    va_list args;
    char buff[BUFSIZ];
    va_start(args, str);
    vsnprintf(buff, sizeof(buff), str, args);
    buff[sizeof(buff)-1] = '\0';
    fputs(buff, stderr);
    va_end(args);
}

void bs_debugmsg(const char *str, ...) {
    va_list args;
    char buff[BUFSIZ];
    //snprintf(buff, 8, "[DEBUG]");
    //buff[BUFSIZ - 1] = '\0';
    va_start(args, str);
    vsnprintf(buff, sizeof(buff), str, args);
    buff[sizeof(buff)-1] = '\0';
    fputs(buff, stderr);
    va_end(args);
}

/* bit vector operations */
void bit_vector_set(unsigned char *vector, unsigned int offset){
    uint32_t byteIndex = offset >> 3;
    uint8_t bitMask = 1 << (offset & 0x00000007);
    vector[byteIndex] |= bitMask;
}

int bs_init(bitshred_t *vdb) {
    memset(vdb->bit_vector, 0, FP_SIZE);
    return 0;
}

int bs_set(bitshred_t *vdb, char *inst_seq){
    unsigned int h1;
    //unsigned int h2;
    //unsigned int h3;

    h1 = djb2((unsigned char *)inst_seq) & (FP_SIZE*8 - 1);
    //h2 = sdbm((unsigned char *)inst_seq) & (FP_SIZE*8 - 1);
    //h3 = jenkins((unsigned char *)inst_seq) & (FP_SIZE*8 - 1);

    bit_vector_set(vdb->bit_vector, h1);
    //bit_vector_set(vdb->bit_vector, h2);
    //bit_vector_set(vdb->bit_vector, h3);

    return 0;
}

/* hash functions */
inline unsigned int djb2(unsigned char *str) {
    unsigned int hash = 5381;
    int c;
    size_t i;

    for(i= 0; i< shredsize; i++) {
        c = *str++;
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }

    return hash;
}

inline void djb2_init(unsigned int *hash) {
    *hash = 5381;
}

inline void djb2_update(unsigned int *hash, unsigned char *str, int size) {
    int c;
    size_t i;

    for(i= 0; i< size; i++) {
        c = *str++;
        *hash = ((*hash << 5) + *hash) + c; /* hash * 33 + c */
    }   
}

inline unsigned int sdbm(unsigned char *str) {
    unsigned int hash = 0;
    int c;
    size_t i;

    for(i= 0; i< shredsize; i++) {
        c = *str++;
        hash = c + (hash << 6) + (hash << 16) - hash;
    }

    return hash;
}

inline unsigned int jenkins(unsigned char *str) {
    uint32_t hash = 0;
    size_t i;
 
    for (i = 0; i < shredsize; i++) {
        hash += str[i];
        hash += (hash << 10);
        hash ^= (hash >> 6);
    }
    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);
    return hash;
}

/* count # of bits set to 1 */
unsigned int bitcount(unsigned int v) {
    unsigned int c;
    v = v - ((v >> 1) & 0x55555555);                    // reuse input as temporary
    v = (v & 0x33333333) + ((v >> 2) & 0x33333333);     // temp
    c = ((v + (v >> 4) & 0xF0F0F0F) * 0x1010101) >> 24; // count
    return c;
}

/* calculate the time difference */
double time_diff(struct timeval new_t, struct timeval old_t) {
    double diff;
    diff = (double)new_t.tv_sec - (double)old_t.tv_sec
           + (double)new_t.tv_usec/1000000 - (double)old_t.tv_usec/1000000;
    return diff;
}
