#ifndef __BS_COMMON_H__
#define __BS_COMMON_H__

#include <sys/time.h>
#include <stdint.h>

#define DB_PATH  "./db"

#define FP_SIZE       (1024*32)   // 32KB
#define FP_PER_BLOCK  1024
#define MAX_SETBITS   0.7

#define EXE_BIN  0
#define EXE_TXT  1

typedef struct bitshred {
    uint8_t bit_vector[FP_SIZE];
    unsigned int nbits;
} bitshred_t;

extern int debug_flag;

#define bs_dbgmsg (!debug_flag) ? (void)0 : bs_debugmsg
#define bs_errmsg bs_verbosemsg

/* bs_common.c */
void bs_msg(const char *str, ...);
void bs_verbosemsg(const char *str, ...);
void bs_debugmsg(const char *str, ...);

inline unsigned int djb2(unsigned char *str);
inline void djb2_init(unsigned int *hash);
inline void djb2_update(unsigned int *hash, unsigned char *str, int size);
inline unsigned int sdbm(unsigned char *str);
inline unsigned int jenkins(unsigned char *str);

void bit_vector_set(unsigned char *vector, unsigned int offset);
int bs_init(bitshred_t *vdb);
int bs_set(bitshred_t *vdb, char *inst_seq);

unsigned int bitcount(unsigned int v);
double time_diff(struct timeval new_t, struct timeval old_t);

#endif
