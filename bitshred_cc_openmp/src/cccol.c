#include "bs_common.h"

uint64_t *global_tg = NULL;
unsigned int global_trnum;
unsigned int global_tcnum;
unsigned int *trows_in_each_group = NULL;
unsigned int *tcols_in_each_group = NULL;
double *trows_before_cost = NULL;

int opt_trow_group(int cur_trow_label, uint64_t *trow_stat) {
    int i, j;
    int trows_in_cur_group;
    int trows_in_pro_group;
    int tcols_in_group;
    int opt_trow_label;

    uint64_t num1, num0;
    //double before_cost = 0;
    double after_cost = 0;
    double tmp_cost;
    double min_cost;
    double cost;

    trows_in_cur_group = trows_in_each_group[cur_trow_label];
    for(i=0; i<global_tcnum; i++) {
        tcols_in_group = tcols_in_each_group[i];
//        num1 = global_tg[cur_trow_label*global_tcnum+i];
//        num0 = (uint64_t)trows_in_cur_group*tcols_in_group - num1;
//        if (num1!=0 && num0!=0)
//            before_cost += num1*log2((num1+num0)/(double)num1) + num0*log2((num1+num0)/(double)num0);
        num1 = global_tg[cur_trow_label*global_tcnum+i]-trow_stat[i];
        num0 = (uint64_t)(trows_in_cur_group-1)*tcols_in_group - num1;
        if (num1!=0 && num0!=0)
            after_cost += num1*log2((num1+num0)/(double)num1) + num0*log2((num1+num0)/(double)num0);
    }
    tmp_cost = after_cost - trows_before_cost[cur_trow_label];

    min_cost = 0;
    opt_trow_label = cur_trow_label;
    for(i=0; i<global_trnum; i++) {
        if(i==cur_trow_label) continue;
        trows_in_pro_group = trows_in_each_group[i];
        //before_cost = 0;
        after_cost = 0;

        for(j=0; j<global_tcnum; j++) {
            tcols_in_group = tcols_in_each_group[j];
//            num1 = global_tg[i*global_tcnum+j];
//            num0 = (uint64_t)trows_in_pro_group*tcols_in_group - num1;
//            if (num1!=0 && num0!=0)
//                before_cost += num1*log2((num1+num0)/(double)num1) + num0*log2((num1+num0)/(double)num0);
            num1 = global_tg[i*global_tcnum+j]+trow_stat[j];
            num0 = (uint64_t)(trows_in_pro_group+1)*tcols_in_group - num1;
            if (num1!=0 && num0!=0)
                after_cost += num1*log2((num1+num0)/(double)num1) + num0*log2((num1+num0)/(double)num0);
        }
        cost = tmp_cost + (after_cost - trows_before_cost[i]);

        if(cost < min_cost) {
            opt_trow_label = i;
            min_cost = cost;
        }
        else if(cost == min_cost) {
            opt_trow_label = (opt_trow_label < i) ? opt_trow_label : i;
        }
    }
    return opt_trow_label;
}

int cccol(int outer_iter_num, int inner_iter_num) {
    int idx, idx2;
    int chunk;
    int tid;
    int new_trow_label;
    int offset;
    uint64_t *local_tg = NULL;
    uint64_t *tmp_global_tg = NULL;
    int *trows_selected = NULL;
    unsigned int *global_tr = global_c;
    unsigned int *global_tc = global_r;
    int trows_in_group;
    int tcols_in_group;
    uint64_t num1, num0;
    double before_cost = 0;

    struct timeval stime, etime;
    double sec_elapsed = 0;

    gettimeofday(&stime, NULL);

    global_trnum = global_cnum;
    global_tcnum = global_rnum;
    trows_in_each_group = cols_in_each_group;
    tcols_in_each_group = rows_in_each_group;

    chunk = (FP_SIZE*8)/col_max_threads;
    omp_set_num_threads(col_max_threads);
    bs_msg("[cccol.%d.%d] %d row / %d col", outer_iter_num, inner_iter_num, global_rnum, global_cnum);

    if((global_tg = (uint64_t *)malloc(sizeof(uint64_t)*global_tcnum*global_trnum))==NULL) {
        perror("global_tg malloc()");
        exit(EXIT_FAILURE);
    }
    for(idx=0; idx<global_rnum; idx++)
        for(idx2=0; idx2<global_cnum; idx2++)
            global_tg[idx2*global_tcnum+idx] = global_g[idx*global_cnum+idx2];
    memset(global_g, 0, sizeof(uint64_t)*global_cnum*global_rnum);

    if((trows_before_cost = (double *)malloc(global_trnum*sizeof(double)))==NULL) {
        perror("trows_before_cost malloc()");
        exit(EXIT_FAILURE);
    }

    // calculate before trow groups cost
    for(idx=0; idx<global_trnum; idx++) {
        trows_in_group = trows_in_each_group[idx];
        before_cost = 0;
        for(idx2=0; idx2<global_tcnum; idx2++) {
            tcols_in_group = tcols_in_each_group[idx2];
            num1 = global_tg[idx*global_tcnum+idx2];
            num0 = (uint64_t)trows_in_group*tcols_in_group - num1;
            if (num1!=0 && num0!=0)
                before_cost += num1*log2((num1+num0)/(double)num1) + num0*log2((num1+num0)/(double)num0);
        }
        trows_before_cost[idx] = before_cost;
    }

    if((local_tg = (uint64_t *)malloc(sizeof(uint64_t)*(global_tcnum*global_trnum*col_max_threads)))==NULL) {
        perror("local_tg malloc()");
        exit(EXIT_FAILURE);
    }
    if((tmp_global_tg = (uint64_t *)calloc(global_tcnum*global_trnum, sizeof(uint64_t)))==NULL) {
        perror("tmp_global_tg calloc()");
        exit(EXIT_FAILURE);
    }
    if((trows_selected = (int *)calloc(global_trnum, sizeof(int)))==NULL) {
        perror("trows_selected calloc()");
        exit(EXIT_FAILURE);
    }

    #pragma omp parallel default(shared) private(tid)
    {
        tid = omp_get_thread_num();
        memset(local_tg+(tid*global_tcnum*global_trnum), 0, sizeof(uint64_t)*global_tcnum*global_trnum);
    }

    #pragma omp parallel default(shared) private(tid)
    {
        int i, j;
        uint64_t *thread_local_tg;
        int chunkoffset;
        int bit_id;
        uint32_t byteIndex;
        uint8_t bitMask;
        uint64_t *trow_stat = NULL;
        int cur_trow_label;
        int opt_trow_label;
        tid = omp_get_thread_num();

        //thread_bs_fp = bs_fp+(tid*chunk);
        thread_local_tg = local_tg+(tid*global_tcnum*global_trnum);

        if((trow_stat=(uint64_t*)calloc(global_tcnum*chunk, sizeof(uint64_t)))==NULL) {
            perror("trow_stat calloc()");
            exit(EXIT_FAILURE);
        }

        for(i=0; i<nsamples; i++) {
            chunkoffset = (chunk/8)*tid;
            for(j=0; j<chunk; j++) {
                byteIndex = j >> 3;
                bitMask = 1 << (j & 0x00000007);
                if ((bs_fp+i)->bit_vector[chunkoffset+byteIndex] & bitMask) {
                    trow_stat[j*global_tcnum+global_tc[i]] += 1;
                }
            }
        }
        //compute row statistics
        for(i=0; i<chunk; i++) {
            bit_id = tid*chunk+i;
            //find the optimal column group
            cur_trow_label = global_tr[bit_id];
            opt_trow_label = opt_trow_group(cur_trow_label, trow_stat+(i*global_tcnum));
            global_tr[bit_id] = opt_trow_label;
            if (!trows_selected[opt_trow_label]) {
                #pragma omp critical
                trows_selected[opt_trow_label] = 1;
            }
            for(j=0; j<global_tcnum; j++)
                thread_local_tg[opt_trow_label*global_tcnum+j] += trow_stat[i*global_tcnum+j];
        }
        free(trow_stat);
    }

    for(tid=0; tid<col_max_threads; tid++) {
        offset = tid*global_tcnum*global_trnum;
        for(idx=0; idx<global_tcnum*global_trnum; idx++)
            tmp_global_tg[idx] += local_tg[offset+idx];
    }

    new_trow_label = 0;
    for(idx=0; idx<global_trnum; idx++) {
        if (trows_selected[idx]) {
            for(idx2=0; idx2<global_tcnum; idx2++) 
                global_tg[new_trow_label*global_tcnum+idx2] = tmp_global_tg[idx*global_tcnum+idx2];
            trows_selected[idx] = new_trow_label;
            new_trow_label++;
        }
    }

    memset(trows_in_each_group, 0, sizeof(unsigned int)*global_trnum);
    global_trnum = new_trow_label;
    for(idx=0; idx<FP_SIZE*8; idx++) {
        global_tr[idx] = trows_selected[global_tr[idx]];
        trows_in_each_group[global_tr[idx]] += 1;
    }

    global_cnum = global_trnum;
    global_rnum = global_tcnum;
    global_c = global_tr;
    global_r = global_tc;
    cols_in_each_group = trows_in_each_group;
    rows_in_each_group = tcols_in_each_group;
    
    for(idx=0; idx<global_trnum; idx++)
        for(idx2=0; idx2<global_tcnum; idx2++)
            global_g[idx2*global_cnum+idx] = global_tg[idx*global_tcnum+idx2];
    
    bs_msg(" ... %d row / %d col", global_rnum, global_cnum);

    gettimeofday(&etime, NULL);
    sec_elapsed = time_diff(etime, stime);
    bs_msg(" @ %um %.1fs\n",
           ((unsigned int)sec_elapsed / 60),
           ((sec_elapsed-(unsigned int)sec_elapsed)+(unsigned int)sec_elapsed%60));

    free(local_tg);
    free(global_tg);
    free(tmp_global_tg);
    free(trows_selected);
    free(trows_before_cost);
    return 0;
}
