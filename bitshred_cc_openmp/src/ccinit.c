#include "bs_common.h"

int ccinit() {
    int *rowsplit;
    int *colsplit;
    uint64_t *local_g = NULL;
    int nrows_per_group;
    int ncols_per_group;
    int idx;
    int chunk;
    int tid;
    int row_label;
    int col_label;
    int offset;

    chunk = nsamples/row_max_threads;
    omp_set_num_threads(row_max_threads);
    bs_msg("[ccinit] %d row / %d col\n", global_rnum, global_cnum, row_max_threads);

    if((rowsplit=(int *)malloc(sizeof(int)*global_rnum))==NULL) {
        perror("rowsplit malloc()");
        exit(EXIT_FAILURE);
    }
    if((colsplit=(int *)malloc(sizeof(int)*global_cnum))==NULL) {
        perror("colsplit malloc()");
        exit(EXIT_FAILURE);
    }
    if((local_g = (uint64_t *)malloc(sizeof(uint64_t)*(global_cnum*global_rnum*row_max_threads)))==NULL) {
        perror("row_stat malloc()");
        exit(EXIT_FAILURE);
    }

    nrows_per_group = nsamples/global_rnum;
    ncols_per_group = (FP_SIZE*8)/global_cnum;

    srand(time(NULL));
    for(idx=0; idx<global_rnum-1; idx++) 
        rowsplit[idx] = rand()%nrows_per_group + (idx*nrows_per_group);
    rowsplit[global_rnum-1] = nsamples;
    for(idx=0; idx<global_cnum-1; idx++)
        colsplit[idx] = rand()%ncols_per_group + (idx*ncols_per_group);
    colsplit[global_cnum-1] = FP_SIZE*8;

    #pragma omp parallel default(shared) private(tid)
    {
        tid = omp_get_thread_num();
        memset(local_g+(tid*global_cnum*global_rnum), 0, sizeof(uint64_t)*global_cnum*global_rnum);
    }

    #pragma omp parallel default(shared) private(tid, row_label, col_label)
    {
        int i, j;
        tid = omp_get_thread_num();
        bitshred_t *thread_bs_fp;
        uint64_t *thread_local_g;
        int sample_id;
        uint32_t byteIndex;
        uint8_t bitMask;

        thread_bs_fp = bs_fp+(tid*chunk);
        thread_local_g = local_g+(tid*global_cnum*global_rnum);

        //compute row statistics
        row_label = 0;
        for(i=0; i<chunk; i++) {
            sample_id = tid*chunk+i;
            while(sample_id>=rowsplit[row_label]) row_label++;
            col_label = 0;
            for(j=0; j<FP_SIZE*8; j++) {
                byteIndex = j >> 3;
                bitMask = 1 << (j & 0x00000007);
                if ((thread_bs_fp+i)->bit_vector[byteIndex] & bitMask) {
                    while(j>=colsplit[col_label]) col_label++;
                    thread_local_g[row_label*global_cnum+col_label] += 1;
                }
            }
        }
    }

    //update global G
    for(tid=0; tid<row_max_threads; tid++) {
        offset = tid*global_cnum*global_rnum;
        if (tid==0) {
            for(idx=0; idx<global_cnum*global_rnum; idx++)
                global_g[idx] = local_g[offset+idx];
        }
        else {
            for(idx=0; idx<global_cnum*global_rnum; idx++)
                global_g[idx] += local_g[offset+idx];
        }
    }

    row_label = 0;
    for(idx=0; idx<nsamples; idx++) {
        if(row_label!=global_rnum-1 && idx>=rowsplit[row_label])
            row_label++;
        global_r[idx] = row_label;
        rows_in_each_group[row_label] += 1;
    }

    col_label = 0;
    for(idx=0; idx<FP_SIZE*8; idx++) {
        if(col_label!=global_cnum-1 && idx>=colsplit[col_label])
            col_label++;
        global_c[idx] = col_label;
        cols_in_each_group[col_label] += 1;
    }

    free(rowsplit);
    free(colsplit);
    free(local_g);
    return 0;
}
