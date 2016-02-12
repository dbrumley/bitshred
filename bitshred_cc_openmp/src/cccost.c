#include "bs_common.h"

unsigned int *rows_in_each_group_sorted;
unsigned int *cols_in_each_group_sorted;

int logstar2(double n) {
    int l = 0;
    while (n>1) {
        l++;
        n = log2(n);
    }
    return l;
}

int rows_in_each_group_bar(int i) {
    int t;
    int sum = 0;
    for(t=i; t<global_rnum; t++) {
        sum += rows_in_each_group_sorted[t];
    }
    sum = sum - (global_rnum-1) + i;
    return sum;
}

int cols_in_each_group_bar(int j) {
    int t;
    int sum = 0;
    for(t=j; t<global_cnum; t++) {
        sum += cols_in_each_group_sorted[t];
    }
    sum = sum - (global_cnum-1) + j;
    return sum;
}

double total_code_length() {
    int i, j;
    int rows_in_group;
    int cols_in_group;

    uint64_t num1, num0;
    double cost = 0;

    for(i=0; i<global_rnum; i++) {
        rows_in_group = rows_in_each_group[i];
        for(j=0; j<global_cnum; j++) {
            cols_in_group = cols_in_each_group[j];

            num1 = global_g[i*global_cnum+j];
            num0 = (uint64_t)rows_in_group*cols_in_group - num1;
            if (num1!=0 && num0!=0)
                cost += num1*log2((num1+num0)/(double)num1) + num0*log2((num1+num0)/(double)num0);
        }
    }
    return cost;
}

int compare (const void *a, const void *b) {
    return (*(unsigned int *)b - *(unsigned int *)a);
}

double cccost(int outer_iter_num, int inner_iter_num) {
    int i, j;
    int rows_in_group;
    int cols_in_group;

    uint64_t num1, num0;
    double cost = 0;
    uint64_t num_in_submatrix;

    struct timeval stime, etime;
    double sec_elapsed = 0;

    gettimeofday(&stime, NULL);

    bs_msg("[cccost.%d.%d] %d row / %d col: ", outer_iter_num, inner_iter_num, global_rnum, global_cnum);

    if((rows_in_each_group_sorted=(unsigned int*)malloc(sizeof(unsigned int)*global_rnum))==NULL) {
        perror("rows_in_each_group_sorted malloc()");
        exit(EXIT_FAILURE);
    }
    for(i=0; i<global_rnum; i++)
        rows_in_each_group_sorted[i] = rows_in_each_group[i];
    
    if((cols_in_each_group_sorted=(unsigned int*)malloc(sizeof(unsigned int)*global_cnum))==NULL) {
        perror("cols_in_each_group_sorted malloc()");
        exit(EXIT_FAILURE);
    }
    for(j=0; j<global_cnum; j++)
        cols_in_each_group_sorted[j] = cols_in_each_group[j];

    cost = logstar2(global_rnum) + logstar2(global_cnum);
    
    qsort(rows_in_each_group_sorted, global_rnum, sizeof(unsigned int), compare);
    qsort(cols_in_each_group_sorted, global_cnum, sizeof(unsigned int), compare);

    for(i=0; i<global_rnum-1; i++)
        cost += ceil(log2(rows_in_each_group_bar(i)));
    for(j=0; j<global_cnum-1; j++)
        cost += ceil(log2(cols_in_each_group_bar(j)));

    for(i=0; i<global_rnum; i++) {
        rows_in_group = rows_in_each_group[i];
        for(j=0; j<global_cnum; j++) {
            cols_in_group = cols_in_each_group[j];

            num_in_submatrix = (uint64_t)rows_in_group*cols_in_group;
            cost += ceil(log2(num_in_submatrix+1));
            num1 = global_g[i*global_cnum+j];
            num0 = num_in_submatrix - num1;
            if (num1!=0 && num0!=0)
                cost += num1*log2((num1+num0)/(double)num1) + num0*log2((num1+num0)/(double)num0);
        }
    }
    bs_msg("%.2f", cost);

    gettimeofday(&etime, NULL);
    sec_elapsed = time_diff(etime, stime);
    bs_msg(" @ %um %.1fs\n",
           ((unsigned int)sec_elapsed / 60),
           ((sec_elapsed-(unsigned int)sec_elapsed)+(unsigned int)sec_elapsed%60));

    free(rows_in_each_group_sorted);
    free(cols_in_each_group_sorted);
    return cost;
}
