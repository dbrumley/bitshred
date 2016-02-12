#ifndef __SHRED_H__
#define __SHRED_H__

#include "bincode.h"

#define SHRED_BIN      4
#define SHRED_TXT      1
#define WINDOW_SIZE    1
#define MAX_LINEBUF    8192

typedef struct shred {
    //char *inst_seq;
    uint32_t hash;
    unsigned int offset;
} shred_t;

typedef struct {
    char data[MAX_LINEBUF];
    unsigned int offset;
} line_t;

/* shred.c */
int shred_section(bincode_t *bin, shred_t **shredp, unsigned int *filesize, unsigned int *secsize);
int shred_txt(FILE *fp, shred_t **shredp);

#endif
