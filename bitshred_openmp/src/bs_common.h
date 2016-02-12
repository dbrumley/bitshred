#ifndef __BS_COMMON_H__
#define __BS_COMMON_H__

#include <sys/time.h>
#include <stdint.h>

#define CACHE_SIZE    (2*1024*1024)
#define FP_SIZE       (1024*32)    // 32KB
#define FP_PER_FILE   2048
#define VIRUS_COUNT   1024
#define SHRED_SIZE    16
#define WINDOW_SIZE   12
#define MAX_THREADS   8

typedef struct bitshred {
    uint8_t bit_vector[FP_SIZE];
} bitshred_t;

typedef struct sample {
    int sample_id;
    char sample_path[256];
} sample_t;

typedef struct similarity {
    int sid_a;
    int sid_b;
    float sim;
} similarity_t;

typedef struct block {
    int block_idV;
    int block_idH;
} block_t;

extern int debug_flag;

#define bs_dbgmsg (!debug_flag) ? (void)0 : bs_debugmsg
#define bs_verbosemsg    bs_errmsg

/* bs_common.c */
void bs_msg(const char *str, ...);
void bs_errmsg(const char *str, ...);
void bs_debugmsg(const char *str, ...);

inline unsigned int djb2(unsigned char *str);
inline unsigned int sdbm(unsigned char *str);
inline unsigned int jenkins(unsigned char *str);

inline void bit_vector_set(unsigned char *vector, unsigned int offset);
int bs_init(bitshred_t *vdb);
int bs_set(bitshred_t *vdb, char *inst_seq);

unsigned int bitcount(unsigned int v);
double time_diff(struct timeval new_t, struct timeval old_t);

#endif
