#ifndef __BS_COMMON_H__
#define __BS_COMMON_H__

#include <sys/time.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <omp.h>
#include <math.h>
#include <time.h>

#define CACHE_SIZE           (2*1024*1024)
//#define FP_SIZE              (1024*8)    // 8KB
//#define FP_SIZE              (1024*32)    // 32KB
#define FP_SIZE              2097152
#define VIRUS_COUNT          1024
#define SHRED_SIZE           4
#define WINDOW_SIZE          1
#define ROW_MAX_THREADS      8
#define COL_MAX_THREADS      8
#define ROW_SPLIT            0x01
#define COL_SPLIT            0x02
#define INNER_COST_THRESHOLD 1.0
#define OUTER_COST_THRESHOLD 1.0
//#define INNER_COST_THRESHOLD 0.999
//#define OUTER_COST_THRESHOLD 0.99999

typedef struct bitshred {
    uint8_t bit_vector[FP_SIZE];
} bitshred_t;

typedef struct sample {
    int sample_id;
    char sample_path[256];
} sample_t;

extern int debug_flag;
extern unsigned int shredsize; 
extern unsigned int windowsize; 

extern int row_max_threads;
extern int col_max_threads;

extern int nsamples;
extern bitshred_t *bs_fp;

extern uint64_t *global_g;
extern unsigned int *global_r;
extern unsigned int *global_c;
extern unsigned int global_rnum;
extern unsigned int global_cnum;
extern unsigned int *rows_in_each_group;
extern unsigned int *cols_in_each_group;

extern uint64_t *prev_global_g;
extern unsigned int *prev_global_r;
extern unsigned int *prev_global_c;
extern unsigned int prev_global_rnum;
extern unsigned int prev_global_cnum;
extern unsigned int *prev_rows_in_each_group;
extern unsigned int *prev_cols_in_each_group;

#define bs_dbgmsg (!debug_flag) ? (void)0 : bs_debugmsg
#define bs_verbosemsg    bs_errmsg

/* cc */
int read_sampledir(char *cur_dir, sample_t **sample_list, int *nsamples);
int compare_filename(const void *a, const void *b);
int ccgen(char *db_path, sample_t *sample_list);
int ccread(char *db_path, sample_t *sample_list, int fp_per_file);
int ccgen_ascii(char *db_path, sample_t *sample_list);
int ccinit();
int ccrow(int outer_iter_num, int inner_iter_num);
int cccol(int outer_iter_num, int inner_iter_num);
double cccost(int outer_iter_num, int inner_iter_num);
int ccsplit(int split_group, int num_split);
int ccpermute(char *db_path, int outer_iter_num, int inner_iter_num);

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
int bs_output(char *db_path, int outer_iter_num, int inner_iter_num);

#endif
