#include "bs_common.h"

double *rows_before_cost = NULL;

int opt_row_group(int cur_row_label, uint64_t *row_stat) {
    int i, j;
    int rows_in_cur_group;
    int rows_in_pro_group;
    int cols_in_group;
    int opt_row_label;

    uint64_t num1, num0;
//    double before_cost = 0;
    double after_cost = 0;
    double tmp_cost;
    double min_cost;
    double cost;

    rows_in_cur_group = rows_in_each_group[cur_row_label];
    for(i=0; i<global_cnum; i++) {
        cols_in_group = cols_in_each_group[i];
//        num1 = global_g[cur_row_label*global_cnum+i];
//        num0 = (uint64_t)rows_in_cur_group*cols_in_group - num1;
//        if (num1!=0 && num0!=0)
//            before_cost += num1*log2((num1+num0)/(double)num1) + num0*log2((num1+num0)/(double)num0);
        num1 = global_g[cur_row_label*global_cnum+i]-row_stat[i];
        num0 = (uint64_t)(rows_in_cur_group-1)*cols_in_group - num1;
        if (num1!=0 && num0!=0)
            after_cost += num1*log2((num1+num0)/(double)num1) + num0*log2((num1+num0)/(double)num0);
    }
    tmp_cost = after_cost - rows_before_cost[cur_row_label];

    min_cost = 0;
    opt_row_label = cur_row_label;
    for(i=0; i<global_rnum; i++) {
        if(i==cur_row_label) continue;
        rows_in_pro_group = rows_in_each_group[i];
//        before_cost = 0;
        after_cost = 0;

        for(j=0; j<global_cnum; j++) {
            cols_in_group = cols_in_each_group[j];
//            num1 = global_g[i*global_cnum+j];
//            num0 = (uint64_t)rows_in_pro_group*cols_in_group - num1;
//            if (num1!=0 && num0!=0)
//                before_cost += num1*log2((num1+num0)/(double)num1) + num0*log2((num1+num0)/(double)num0);
            num1 = global_g[i*global_cnum+j] + row_stat[j];
            num0 = (uint64_t)(rows_in_pro_group+1)*cols_in_group - num1;
            if (num1!=0 && num0!=0)
                after_cost += num1*log2((num1+num0)/(double)num1) + num0*log2((num1+num0)/(double)num0);
        }
        cost = tmp_cost + (after_cost - rows_before_cost[i]);

        if(cost < min_cost) {
            opt_row_label = i;
            min_cost = cost;
        }
        else if(cost == min_cost) {
            opt_row_label = (opt_row_label < i) ? opt_row_label : i;
        }
    }
    return opt_row_label;
}

int ccrow(int outer_iter_num, int inner_iter_num) {
    int idx, idx2;
    int chunk;
    int tid;
    int new_row_label;
    int offset;
    uint64_t *local_g = NULL;
    uint64_t *tmp_global_g = NULL;
    int *rows_selected = NULL;
    int rows_in_group;
    int cols_in_group;
    uint64_t num1, num0;
    double before_cost = 0;

    struct timeval stime, etime;
    double sec_elapsed = 0;

    gettimeofday(&stime, NULL);

    chunk = nsamples/row_max_threads;
    omp_set_num_threads(row_max_threads);
    bs_msg("[ccrow.%d.%d] %d row / %d col", outer_iter_num, inner_iter_num, global_rnum, global_cnum);

    if((rows_before_cost = (double *)malloc(global_rnum*sizeof(double)))==NULL) {
        perror("rows_before_cost malloc()");
        exit(EXIT_FAILURE);
    }

    // calculate before trow groups cost
    for(idx=0; idx<global_rnum; idx++) {
        rows_in_group = rows_in_each_group[idx];
        before_cost = 0;
        for(idx2=0; idx2<global_cnum; idx2++) {
            cols_in_group = cols_in_each_group[idx2];
            num1 = global_g[idx*global_cnum+idx2];
            num0 = (uint64_t)rows_in_group*cols_in_group - num1;
            if (num1!=0 && num0!=0)
                before_cost += num1*log2((num1+num0)/(double)num1) + num0*log2((num1+num0)/(double)num0);
        }
        rows_before_cost[idx] = before_cost;
    }

    if((local_g = (uint64_t *)malloc(sizeof(uint64_t)*(global_cnum*global_rnum*row_max_threads)))==NULL) {
        perror("local_g malloc()");
        exit(EXIT_FAILURE);
    }
    if((tmp_global_g = (uint64_t *)calloc(global_cnum*global_rnum, sizeof(uint64_t)))==NULL) {
        perror("tmp_global_g calloc()");
        exit(EXIT_FAILURE);
    }
    if((rows_selected = (int *)calloc(global_rnum, sizeof(int)))==NULL) {
        perror("rows_removed calloc()");
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
        tid = omp_get_thread_num();
        bitshred_t *thread_bs_fp;
        uint64_t *thread_local_g;
        int sample_id;
        uint32_t byteIndex;
        uint8_t bitMask;
        uint64_t *row_stat = NULL;
        int cur_row_label;
        int opt_row_label;

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
            //find the optimal row group
            cur_row_label = global_r[sample_id];
            opt_row_label = opt_row_group(cur_row_label, row_stat);
            global_r[sample_id] = opt_row_label;
            if (!rows_selected[opt_row_label]) {
                #pragma omp critical
                rows_selected[opt_row_label] = 1;
            }
            for(j=0; j<global_cnum; j++)
                thread_local_g[opt_row_label*global_cnum+j] += row_stat[j];
        }
        free(row_stat);
    }

    for(tid=0; tid<row_max_threads; tid++) {
        offset = tid*global_cnum*global_rnum;
        for(idx=0; idx<global_cnum*global_rnum; idx++)
            tmp_global_g[idx] += local_g[offset+idx];
    }

    new_row_label = 0;
    for(idx=0; idx<global_rnum; idx++) {
        if (rows_selected[idx]) {
            for(idx2=0; idx2<global_cnum; idx2++) 
                global_g[new_row_label*global_cnum+idx2] = tmp_global_g[idx*global_cnum+idx2];
            rows_selected[idx] = new_row_label;
            new_row_label++;
        }
    }

    memset(rows_in_each_group, 0, sizeof(unsigned int)*global_rnum);
    global_rnum = new_row_label;
    for(idx=0; idx<nsamples; idx++) {
        global_r[idx] = rows_selected[global_r[idx]];
        rows_in_each_group[global_r[idx]] += 1;
    }

    bs_msg(" ... %d row / %d col", global_rnum, global_cnum);

    gettimeofday(&etime, NULL);
    sec_elapsed = time_diff(etime, stime);
    bs_msg(" @ %um %.1fs\n",
           ((unsigned int)sec_elapsed / 60),
           ((sec_elapsed-(unsigned int)sec_elapsed)+(unsigned int)sec_elapsed%60));

    free(local_g);
    free(tmp_global_g);
    free(rows_selected);
    free(rows_before_cost);
    return 0;
}
