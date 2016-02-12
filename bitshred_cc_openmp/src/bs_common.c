#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <inttypes.h>
#include "bs_common.h"

int debug_flag = 0;

extern int nsamples;
extern uint64_t *global_g;
extern unsigned int *global_r;
extern unsigned int *global_c;
extern unsigned int global_rnum;
extern unsigned int global_cnum;

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

void bs_errmsg(const char *str, ...) {
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

/* bit-vector operations */
inline void bit_vector_set(unsigned char *vector, unsigned int offset){
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

/* Hash functions */
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

/* Count # of bits set to 1 */
inline unsigned int bitcount(unsigned int v) {
    unsigned int c;
    v = v - ((v >> 1) & 0x55555555);                    // reuse input as temporary
    v = (v & 0x33333333) + ((v >> 2) & 0x33333333);     // temp
    c = ((v + (v >> 4) & 0xF0F0F0F) * 0x1010101) >> 24; // count
    return c;
}

double time_diff(struct timeval new_t, struct timeval old_t) {
    double diff;
    diff = (double)new_t.tv_sec - (double)old_t.tv_sec
           + (double)new_t.tv_usec/1000000 - (double)old_t.tv_usec/1000000;
    return diff;
}

int bs_output(char *db_path, int outer_iter_num, int inner_iter_num) {
    FILE *fp;
    char buf[256];
    unsigned int i, j, offset;

    sprintf(buf, "%s/global/g_%d_%d_%d_%d", db_path, outer_iter_num, inner_iter_num, global_rnum, global_cnum);
    if((fp=fopen(buf, "w"))==NULL) {
        perror("global_g fopen()");
        exit(EXIT_FAILURE);
    }
    for(i=0; i<global_rnum; i++) {
        offset = i*global_cnum;
        for(j=0; j<global_cnum; j++) {
            fprintf(fp, "%"PRId64, global_g[offset+j]);
            if(j!=global_cnum-1) fprintf(fp, ",");
        }
        fprintf(fp, "\n");
    }
    fclose(fp);

    sprintf(buf, "%s/global/r_%d_%d_%d_%d", db_path, outer_iter_num, inner_iter_num, global_rnum, global_cnum);
    if((fp=fopen(buf, "w"))==NULL) {
        perror("global_r fopen()");
        exit(EXIT_FAILURE);
    }
    for(i=0; i<nsamples; i++) {
        fprintf(fp, "%u", global_r[i]);
        if(i!=nsamples-1) fprintf(fp, ",");
        else fprintf(fp, "\n");
    }
    fclose(fp);

//    sprintf(buf, "%s/global/rnum_%d_%d_%d_%d", db_path, outer_iter_num, inner_iter_num, global_rnum, global_cnum);
//    if((fp=fopen(buf, "w"))==NULL) {
//        perror("global_rnum fopen()");
//        exit(EXIT_FAILURE);
//    }
//    fprintf(fp, "%u", global_rnum);
//    fclose(fp);

    sprintf(buf, "%s/global/c_%d_%d_%d_%d", db_path, outer_iter_num, inner_iter_num, global_rnum, global_cnum);
    if((fp=fopen(buf, "w"))==NULL) {
        perror("global_c fopen()");
        exit(EXIT_FAILURE);
    }
    for(i=0; i<FP_SIZE*8; i++) {
        fprintf(fp, "%u", global_c[i]);
        if(i!=FP_SIZE*8-1) fprintf(fp, ",");
        else fprintf(fp, "\n");
    }
    fclose(fp);

//    sprintf(buf, "%s/global/cnum_%d_%d_%d_%d", db_path, outer_iter_num, inner_iter_num, global_rnum, global_cnum);
//    if((fp=fopen(buf, "w"))==NULL) {
//        perror("global_cnum fopen()");
//        exit(EXIT_FAILURE);
//    }
//    fprintf(fp, "%u", global_cnum);
//    fclose(fp);

    return 0;
}
