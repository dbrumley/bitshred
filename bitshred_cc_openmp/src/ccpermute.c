#include "bs_common.h"

typedef struct {
    int group;
    float density;
} density_t;

int compare_density(const void *a, const void *b) {
    float res;
    res = ((density_t *)a)->density - ((density_t *)b)->density;
    if (res>0) return -1;
    else if (res<0) return 1;
    else return 0;
}

typedef struct {
    int group;
    uint64_t area;
} area_t;

int compare_area(const void *a, const void *b) {
    int64_t res;
    res = ((area_t *)a)->area - ((area_t *)b)->area;
    if (res>0) return -1;
    else if (res<0) return 1;
    else return 0;
}

int ccpermute(char *db_path, int outer_iter_num, int inner_iter_num) {
    FILE *fp;
    char buf[256];
    sample_t *sample_list = NULL;
    int cnt = 0;
    int fp_per_file = 0;
    int c;
    int n = 0;
    int idx = 0;
    int i, j, group;
    uint64_t area, area_sum;
    int max_area_row;
    float density;
    area_t *row_area;
    density_t *column_density;
    int *row_perm;
    int *column_perm;
    bitshred_t *bs_fp_dominant = NULL;
    bitshred_t *bs_fp_others = NULL;

    //load global G
    if((global_g = (uint64_t *)malloc(sizeof(uint64_t)*global_cnum*global_rnum))==NULL) {
        perror("global_g malloc()");
        exit(EXIT_FAILURE);
    }
    sprintf(buf, "%s/global/g_%d_%d_%d_%d", db_path, outer_iter_num, inner_iter_num, global_rnum, global_cnum);
    if((fp=fopen(buf, "r"))==NULL) {
        perror("global_g fopen()");
        exit(EXIT_FAILURE);
    }
    while ((c = fgetc(fp)) != EOF) {
        if (c==',' || c=='\n') {
            global_g[idx] = n;
            n = 0;
            idx++;
        }
        else {
            n = n*10 + (c-48);
        }
    }
    fclose(fp);

    //calculate # of samples
    sprintf(buf, "%s/adjlist", db_path);
    read_sampledir(buf, &sample_list, &cnt);
    qsort(sample_list, cnt, sizeof(sample_t), compare_filename);
    if((fp=fopen(sample_list[0].sample_path, "r"))==NULL) {
        perror("data fopen()");
        exit(EXIT_FAILURE);
    }
    fseek(fp, 0L, SEEK_END);
    fp_per_file = ftell(fp)/FP_SIZE;
    fclose(fp);
    nsamples = cnt*fp_per_file;

    //read adjacent lists
    if((bs_fp_dominant = (bitshred_t *)malloc(sizeof(bitshred_t)*nsamples)) == NULL){
        perror("bs_fp_dominant malloc()");
        exit(EXIT_FAILURE);
    }
    for(i=0; i<cnt; i++) {
        if((fp=fopen(sample_list[i].sample_path, "r"))==NULL) {
            perror("data fopen()");
            exit(EXIT_FAILURE);
        }
        if(fp_per_file!=(fread(bs_fp_dominant+(i*fp_per_file), sizeof(bitshred_t), fp_per_file, fp))) {
            perror("fread data");
            exit(EXIT_FAILURE);
        }
        fclose(fp);
    }
    if((bs_fp_others = (bitshred_t *)calloc(nsamples, sizeof(bitshred_t))) == NULL){
        perror("bs_fp_others calloc()");
        exit(EXIT_FAILURE);
    }

    //load global r
    if((global_r = (unsigned int *)malloc(sizeof(unsigned int)*nsamples))==NULL) {
        perror("global_r malloc()");
        exit(EXIT_FAILURE);
    }
    if((rows_in_each_group = (unsigned int *)calloc(global_rnum, sizeof(unsigned int)))==NULL) {
        perror("rows_in_each_group calloc()");
        exit(EXIT_FAILURE);
    }
    sprintf(buf, "%s/global/r_%d_%d_%d_%d", db_path, outer_iter_num, inner_iter_num, global_rnum, global_cnum);
    if((fp=fopen(buf, "r"))==NULL) {
        perror("global_r fopen()");
        exit(EXIT_FAILURE);
    }
    n = 0;
    idx = 0;
    while ((c = fgetc(fp)) != EOF) {
        if (c==',' || c=='\n') {
            global_r[idx] = n;
            rows_in_each_group[n] += 1;
            n = 0;
            idx++;
        }
        else {
            n = n*10 + (c-48);
        }
    }
    fclose(fp);

    //load global c
    if((global_c = (unsigned int *)malloc(sizeof(unsigned int)*FP_SIZE*8))==NULL) {
        perror("global_c malloc()");
        exit(EXIT_FAILURE);
    }
    if((cols_in_each_group = (unsigned int *)calloc(global_cnum, sizeof(unsigned int)))==NULL) {
        perror("cols_in_each_group calloc()");
        exit(EXIT_FAILURE);
    }
    sprintf(buf, "%s/global/c_%d_%d_%d_%d", db_path, outer_iter_num, inner_iter_num, global_rnum, global_cnum);
    if((fp=fopen(buf, "r"))==NULL) {
        perror("global_c fopen()");
        exit(EXIT_FAILURE);
    }
    n = 0;
    idx = 0;
    while ((c = fgetc(fp)) != EOF) {
        if (c==',' || c=='\n') {
            global_c[idx] = n;
            cols_in_each_group[n] += 1;
            n = 0;
            idx++;
        }
        else {
            n = n*10 + (c-48);
        }
    }
    fclose(fp);

    //permute row groups based upon area
    if((row_area = (area_t *)malloc(global_rnum*sizeof(area_t)))==NULL) {
        perror("row_area malloc()");
        exit(EXIT_FAILURE);
    }
    for(i=0; i<global_rnum; i++) {
        area_sum = 0;
        for(j=0; j<global_cnum; j++) {
            area = (uint64_t)rows_in_each_group[i]*cols_in_each_group[j];
            density = (float)global_g[i*global_cnum+j] / area;
            if (density > 0.95)
                area_sum += area;
        }
        row_area[i].group = i;
        row_area[i].area = area_sum;
    }
    qsort(row_area, global_rnum, sizeof(area_t), compare_area);
    max_area_row = row_area[0].group;

    if((row_perm = (int *)malloc(global_rnum*sizeof(int)))==NULL) {
        perror("row_perm malloc()");
        exit(EXIT_FAILURE);
    }
    for(i=0; i<global_rnum; i++)
        row_perm[row_area[i].group] = i;
    
    for(i=0; i<nsamples; i++) {
        global_r[i] = row_perm[global_r[i]];
    }

    //permute column groups based upon density
    if((column_density = (density_t *)malloc(global_cnum*sizeof(density_t)))==NULL) {
        perror("column_density malloc()");
        exit(EXIT_FAILURE);
    }
    for(j=0; j<global_cnum; j++) {
        area = (uint64_t)rows_in_each_group[max_area_row]*cols_in_each_group[j];
        density = (float)global_g[max_area_row*global_cnum+j] / area;
        column_density[j].group = j;
        column_density[j].density = density;
    }
    qsort(column_density, global_cnum, sizeof(density_t), compare_density);

    for(idx=0; idx<global_cnum; idx++) {
        if (column_density[idx].density==0) break;
    }

    for(j=idx; j<global_cnum; j++) {
        group = column_density[j].group;
        for(i=0; i<global_rnum; i++) {
            area = (uint64_t)rows_in_each_group[i]*cols_in_each_group[group];
            density = (float)global_g[i*global_cnum+group] / area;
            column_density[j].density += density;
        }
    }
    qsort(column_density+idx, global_cnum-idx, sizeof(density_t), compare_density);

    if((column_perm = (int *)malloc(global_cnum*sizeof(int)))==NULL) {
        perror("column_perm malloc()");
        exit(EXIT_FAILURE);
    }
    for(j=0; j<global_cnum; j++)
        column_perm[column_density[j].group] = j;


    for(j=0; j<FP_SIZE*8; j++) {
        global_c[j] = column_perm[global_c[j]];
    }

    //output the new permutation of global r (with the suffix "new")
    sprintf(buf, "%s/global/r_%d_%d_%d_%d.new", db_path, outer_iter_num, inner_iter_num, global_rnum, global_cnum);
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

    //output the new permutation of global c (with the suffix "new")
    sprintf(buf, "%s/global/c_%d_%d_%d_%d.new", db_path, outer_iter_num, inner_iter_num, global_rnum, global_cnum);
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

    //write new adjacent lists for the dominant group and the other groups
    for(i=0; i<nsamples; i++) {
        if(global_r[i]!=0) {
            memcpy(bs_fp_others+i, bs_fp_dominant+i, sizeof(bitshred_t));
            memset(bs_fp_dominant+i, 0, sizeof(bitshred_t));
        }
    }

    sprintf(buf, "%s/adjlist.new.dominant", db_path);
    if(access(buf, F_OK)) 
        mkdir(buf, S_IRWXU|S_IXGRP|S_IRGRP|S_IROTH|S_IXOTH);

    for(i=0; i<(nsamples/fp_per_file); i++) {
        sprintf(buf, "%s/adjlist.new.dominant/data%d", db_path, i);
        if((fp=fopen(buf, "w"))==NULL) {
            perror("new data fopen()");
            exit(EXIT_FAILURE);
        }
        fwrite(bs_fp_dominant+(i*fp_per_file), sizeof(bitshred_t), fp_per_file, fp);
        fclose(fp);
    }

    sprintf(buf, "%s/adjlist.new.others", db_path);
    if(access(buf, F_OK)) 
        mkdir(buf, S_IRWXU|S_IXGRP|S_IRGRP|S_IROTH|S_IXOTH);

    for(i=0; i<(nsamples/fp_per_file); i++) {
        sprintf(buf, "%s/adjlist.new.others/data%d", db_path, i);
        if((fp=fopen(buf, "w"))==NULL) {
            perror("new data fopen()");
            exit(EXIT_FAILURE);
        }
        fwrite(bs_fp_others+(i*fp_per_file), sizeof(bitshred_t), fp_per_file, fp);
        fclose(fp);
    }

    free(sample_list);
    free(global_g);
    free(global_r);
    free(global_c);
    free(rows_in_each_group);
    free(cols_in_each_group);
    free(row_area);
    free(row_perm);
    free(column_density);
    free(column_perm);
    free(bs_fp_dominant);
    free(bs_fp_others);
    return 0;
}
