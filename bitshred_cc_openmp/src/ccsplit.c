#include "bs_common.h"

typedef struct {
    int group;
    double code_length;
} code_length_t;

typedef struct {
    int new_group;
    int num_moved;
} group_split_t;

double code_length(int row_index, int col_index) {
    int rows_in_group;
    int cols_in_group;

    uint64_t num1, num0;
    double code_length = 0;

    rows_in_group = prev_rows_in_each_group[row_index];
    cols_in_group = prev_cols_in_each_group[col_index];
    num1 = prev_global_g[row_index*prev_global_cnum+col_index];
    num0 = (uint64_t)rows_in_group*cols_in_group - num1;
    if (num1!=0 && num0!=0)
        code_length = num1*log2((num1+num0)/(double)num1) + num0*log2((num1+num0)/(double)num0);

    return code_length;
}

int compare_code_length(const void *a, const void *b) {
    float res;
    res = ((code_length_t *)a)->code_length - ((code_length_t *)b)->code_length;
    if (res>0) return -1;
    else if (res<0) return 1;
    else return 0;
}

int ccsplit(int split_group, int num_split) {
    int idx;
    int chunk;
    uint64_t *local_g = NULL;
    int tid;
    int i,j;
    int offset;

    double cur_code_length;
//    double max_code_length;
//    int row_group_splitted;
//    int col_group_splitted;
//    unsigned int rows_in_splitted_group;
//    unsigned int cols_in_splitted_group;

    code_length_t *code_len;
    group_split_t *grp_split;
    int grp;

    struct timeval stime, etime;
    double sec_elapsed = 0;

    gettimeofday(&stime, NULL);

    chunk = nsamples/row_max_threads;
    omp_set_num_threads(row_max_threads);
    bs_msg("[ccsplit] %d row / %d col => %d row / %d col", prev_global_rnum, prev_global_cnum, global_rnum, global_cnum);

    if((global_g = (uint64_t *)calloc(global_cnum*global_rnum, sizeof(uint64_t)))==NULL) {
        perror("global_g malloc()");
        exit(EXIT_FAILURE);
    }       
    if((global_r = (unsigned int *)malloc(sizeof(unsigned int)*nsamples))==NULL) {
        perror("global_r malloc()");
        exit(EXIT_FAILURE);
    }
    if((global_c = (unsigned int *)malloc(sizeof(unsigned int)*FP_SIZE*8))==NULL) {
        perror("global_c malloc()");
        exit(EXIT_FAILURE);
    }       
    if((rows_in_each_group = (unsigned int *)calloc(global_rnum, sizeof(unsigned int)))==NULL) {
        perror("rows_in_each_group calloc()");
        exit(EXIT_FAILURE);
    }               
    if((cols_in_each_group = (unsigned int *)calloc(global_cnum, sizeof(unsigned int)))==NULL) {
        perror("cols_in_each_group calloc()");
        exit(EXIT_FAILURE);
    }

    //select the group to be splitted
//    max_code_length = 0;
    if (split_group==ROW_SPLIT) {
        if((code_len = (code_length_t *)malloc(prev_global_rnum*sizeof(code_length_t)))==NULL) {
            perror("code_len malloc()");
            exit(EXIT_FAILURE);
        }
        for(i=0; i<prev_global_rnum; i++) {
            cur_code_length = 0;
            for(j=0; j<prev_global_cnum; j++) {
                cur_code_length += code_length(i, j);
            }
            code_len[i].group = i;
            code_len[i].code_length = cur_code_length;
        }
        qsort(code_len, prev_global_rnum, sizeof(code_length_t), compare_code_length);

        bs_msg(" (splitting %d row(s):", num_split);
        if((grp_split = (group_split_t *)malloc(prev_global_rnum*sizeof(group_split_t)))==NULL) {
            perror("grp_split malloc()");
            exit(EXIT_FAILURE);
        }
        for(i=0; i<prev_global_rnum; i++) {
            grp = code_len[i].group;
            if(i<num_split) {
                bs_msg(" %d", grp);
                grp_split[grp].new_group = prev_global_rnum+i;
                grp_split[grp].num_moved = prev_rows_in_each_group[grp]/2;
            }
            else {
                grp_split[grp].new_group = -1;
                grp_split[grp].num_moved = 0;
            }
        }
        bs_msg(")");

        for(i=0; i<nsamples; i++) {
            grp = prev_global_r[i];
            if(grp_split[grp].num_moved) {
                global_r[i] = grp_split[grp].new_group;
                grp_split[grp].num_moved -= 1;
            }
            else {
                global_r[i] = grp;
            }
        }
        for(i=0; i<FP_SIZE*8; i++) {
            global_c[i] = prev_global_c[i];
        }
    }
    else {
        if((code_len = (code_length_t *)malloc(prev_global_cnum*sizeof(code_length_t)))==NULL) {
            perror("code_len malloc()");
            exit(EXIT_FAILURE);
        }
        for(i=0; i<prev_global_cnum; i++) {
            cur_code_length = 0;
            for(j=0; j<prev_global_rnum; j++) {
                cur_code_length += code_length(j, i);
            }
            code_len[i].group = i;
            code_len[i].code_length = cur_code_length;
        }
        qsort(code_len, prev_global_cnum, sizeof(code_length_t), compare_code_length);

        bs_msg(" (splitting %d col(s)", num_split);
        if((grp_split = (group_split_t *)malloc(prev_global_cnum*sizeof(group_split_t)))==NULL) {
            perror("grp_split malloc()");
            exit(EXIT_FAILURE);
        }
        for(i=0; i<prev_global_cnum; i++) {
            grp = code_len[i].group;
            if(i<num_split) {
                bs_msg(" %d", grp);
                grp_split[grp].new_group = prev_global_cnum+i;
                grp_split[grp].num_moved = prev_cols_in_each_group[grp]/2;
            }
            else {
                grp_split[grp].new_group = -1;
                grp_split[grp].num_moved = 0;
            }
        }
        bs_msg(")");

        for(i=0; i<FP_SIZE*8; i++) {
            grp = prev_global_c[i];
            if(grp_split[grp].num_moved) {
                global_c[i] = grp_split[grp].new_group;
                grp_split[grp].num_moved -= 1;
            }
            else {
                global_c[i] = grp;
            }
        }
        for(i=0; i<nsamples; i++) {
            global_r[i] = prev_global_r[i];
        }
    }

    free(code_len);
    free(grp_split);

    if((local_g = (uint64_t *)malloc(sizeof(uint64_t)*(global_cnum*global_rnum*row_max_threads)))==NULL) {
        perror("local_g malloc()");
        exit(EXIT_FAILURE);
    }

    #pragma omp parallel default(shared) private(tid)
    {
        tid = omp_get_thread_num();
        memset(local_g+(tid*global_cnum*global_rnum), 0, sizeof(uint64_t)*global_cnum*global_rnum);
    }

    #pragma omp parallel default(shared) private(tid)
    {
        int i, j;
        int sample_id;
        tid = omp_get_thread_num();
        bitshred_t *thread_bs_fp;
        uint64_t *thread_local_g;
        uint32_t byteIndex;
        uint8_t bitMask;
        uint64_t *row_stat = NULL;

        thread_bs_fp = bs_fp+(tid*chunk);
        thread_local_g = local_g+(tid*global_cnum*global_rnum);

        if((row_stat=(uint64_t*)malloc(sizeof(uint64_t)*global_cnum))==NULL) {
            perror("row_stat malloc()");
            exit(EXIT_FAILURE);
        }

        //compute row statistics
        for(i=0; i<chunk; i++) {
            memset(row_stat, 0, sizeof(uint64_t)*global_cnum);
            sample_id = tid*chunk+i;
            for(j=0; j<FP_SIZE*8; j++) {
                byteIndex = j >> 3;
                bitMask = 1 << (j & 0x00000007);
                if ((thread_bs_fp+i)->bit_vector[byteIndex] & bitMask) {
                    row_stat[global_c[j]] += 1;
                }
            }
            for(j=0; j<global_cnum; j++)
                thread_local_g[global_r[sample_id]*global_cnum+j] += row_stat[j];
        }
        free(row_stat);
    }

    for(tid=0; tid<row_max_threads; tid++) {
        offset = tid*global_cnum*global_rnum;
        for(idx=0; idx<global_cnum*global_rnum; idx++)
            global_g[idx] += local_g[offset+idx];
    }

    for(idx=0; idx<nsamples; idx++) {
        rows_in_each_group[global_r[idx]] += 1;
    }

    for(idx=0; idx<FP_SIZE*8; idx++) {
        cols_in_each_group[global_c[idx]] += 1;
    }

    gettimeofday(&etime, NULL);
    sec_elapsed = time_diff(etime, stime);
    bs_msg(" @ %um %.1fs\n",
           ((unsigned int)sec_elapsed / 60),
           ((sec_elapsed-(unsigned int)sec_elapsed)+(unsigned int)sec_elapsed%60));

    free(local_g);
    return 0;
}
