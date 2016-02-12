#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <getopt.h>

#define FP_SIZE (1024*32)     // in bytes
//#define FP_SIZE (1024*8)     // in bytes
    
char *a_path = NULL;
int a_outer_iter_num;
int a_inner_iter_num;
int a_global_rnum;
int a_global_cnum;
char *b_path = NULL;
int b_outer_iter_num;
int b_inner_iter_num;
int b_global_rnum;
int b_global_cnum;

int new_global_rnum;
int new_global_cnum;
int *new_global_r;
int *new_global_c;

int nsamples;
int fp_per_file;

typedef struct {
    int column;
    int group;
} column_t;

int compare_column(const void *a, const void *b) {
    int res;
    res = ((column_t *)a)->group - ((column_t *)b)->group;
    return res;
}

void output() {
    char *a_bf;
    char *b_bf;
    char *new_bf;
    char buf[128];
    FILE *fp;
    int i;

    if((a_bf = (char *)malloc((size_t)FP_SIZE*nsamples))==NULL) {
        perror("a_bf malloc()");
        exit(EXIT_FAILURE);
    }
    if((b_bf = (char *)malloc((size_t)FP_SIZE*nsamples))==NULL) {
        perror("a_bf malloc()");
        exit(EXIT_FAILURE);
    }
    if((new_bf = (char *)malloc((size_t)FP_SIZE*nsamples))==NULL) {
        perror("a_bf malloc()");
        exit(EXIT_FAILURE);
    }

    fprintf(stderr, "[-] Merging Fingerprints...\n");
    for(i=0; i<nsamples/fp_per_file; i++) {
        snprintf(buf, 128, "%s/adjlist/data%d", a_path, i);
        if((fp = fopen(buf, "r"))==NULL) {
            perror("a adjlist data fopen()");
            exit(EXIT_FAILURE);
        }
        fread(a_bf+(FP_SIZE*fp_per_file)*i, FP_SIZE*fp_per_file, 1, fp);
        fclose(fp);

        snprintf(buf, 128, "%s/adjlist/data%d", b_path, i);
        if((fp = fopen(buf, "r"))==NULL) {
            perror("b adjlist data fopen()");
            exit(EXIT_FAILURE);
        }
        fread(b_bf+(FP_SIZE*fp_per_file)*i, FP_SIZE*fp_per_file, 1, fp);
        fclose(fp);
    }

    for(i=0; i<(FP_SIZE*nsamples)/4; i++) {
        ((unsigned int *)new_bf)[i] = ((unsigned int *)a_bf)[i] | ((unsigned int *)b_bf)[i];
    }

    fprintf(stderr, "[-] Outputting New Fingerprints...\n");
    for(i=0; i<nsamples/fp_per_file; i++) {
        snprintf(buf, 128, "db.new/adjlist/data%d", i);
        if((fp = fopen(buf, "w"))==NULL) {
            perror("new adjlist data fopen()");
            exit(EXIT_FAILURE);
        }
        fwrite(new_bf+(FP_SIZE*fp_per_file)*i, FP_SIZE*fp_per_file, 1, fp);
        fclose(fp);
    }

    fprintf(stderr, "[-] Outputting New Global R...\n");
    snprintf(buf, 128, "db.new/global/r_0_0_%d_%d.new", new_global_rnum, new_global_cnum);
    if((fp=fopen(buf, "w"))==NULL) {
        perror("new_global_r fopen()");
        exit(EXIT_FAILURE);
    }
    for(i=0; i<nsamples; i++) {
        fprintf(fp, "%u", new_global_r[i]);
        if(i!=nsamples-1) fprintf(fp, ",");
        else fprintf(fp, "\n");
    }
    fclose(fp);

    fprintf(stderr, "[-] Outputting New Global C...\n");
    snprintf(buf, 128, "db.new/global/c_0_0_%d_%d.new", new_global_rnum, new_global_cnum);
    if((fp=fopen(buf, "w"))==NULL) {
        perror("new_global_c fopen()");
        exit(EXIT_FAILURE);
    }
    for(i=0; i<FP_SIZE*8; i++) {
        fprintf(fp, "%u", new_global_c[i]);
        if(i!=FP_SIZE*8-1) fprintf(fp, ",");
        else fprintf(fp, "\n");
    }
    fclose(fp);
}

void merge_global_r() {
    FILE *fp;
    char buf[128];
    int i;
    int n, c, index;

    fprintf(stderr, "[-] Merging Global R: A(r_%d_%d_%d_%d)", a_outer_iter_num, a_inner_iter_num, a_global_rnum, a_global_cnum);
    snprintf(buf, 128, "%s/global/r_%d_%d_%d_%d.new", a_path, a_outer_iter_num, a_inner_iter_num, a_global_rnum, a_global_cnum);
    if((fp = fopen(buf, "r"))==NULL) {
        perror("a_global_r fopen()");
        exit(EXIT_FAILURE);
    }
    n = 0;
    index = 0;
    while ((c = fgetc(fp))!=EOF) {
        if (c==',' || c=='\n') {
            if (n==a_global_rnum-1) 
                n = a_global_rnum+b_global_rnum-2;
            new_global_r[index] = n;
            n = 0;
            index++;
        }
        else {
            n = n*10 + (c-48);
        }
    }
    fclose(fp);

    fprintf(stderr, " & B(r_%d_%d_%d_%d) ...", b_outer_iter_num, b_inner_iter_num, b_global_rnum, b_global_cnum);
    snprintf(buf, 128, "%s/global/r_%d_%d_%d_%d.new", b_path, b_outer_iter_num, b_inner_iter_num, b_global_rnum, b_global_cnum);
    if((fp = fopen(buf, "r"))==NULL) {
        perror("b_global_r fopen()");
        exit(EXIT_FAILURE);
    }
    n = 0;
    index = 0;
    while ((c = fgetc(fp))!=EOF) {
        if (c==',' || c=='\n') {
            if (n!=b_global_rnum-1) {
                n += a_global_rnum-1;
                new_global_r[index] = n;
            }
            n = 0;
            index++;
        }
        else {
            n = n*10 + (c-48);
        }
    }
    fclose(fp);

    //append the splitting point to differentiate iterations
    if((fp=fopen("iter_split.log", "a"))==NULL) {
        perror("row_split fopen()");
        exit(EXIT_FAILURE);
    }
    fprintf(fp, "%d\n", a_global_rnum-1);
    fclose(fp);

    new_global_rnum = a_global_rnum+b_global_rnum-1;

    fprintf(stderr, "done\n");
}

void merge_global_c() {
    int *a_global_c;
    int *b_global_c;
    column_t *list_c;
    FILE *fp;
    char buf[128];
    int i, j;
    int n, c, index;
    int cnt;

    if((a_global_c=(int *)malloc((FP_SIZE*8)*sizeof(int)))==NULL) {
        perror("a_global_c malloc()");
        exit(EXIT_FAILURE);
    }
    if((b_global_c=(int *)malloc((FP_SIZE*8)*sizeof(int)))==NULL) {
        perror("b_global_c malloc()");
        exit(EXIT_FAILURE);
    }
    if((list_c=(column_t *)malloc((FP_SIZE*8)*sizeof(column_t)))==NULL) {
        perror("list_c malloc()");
        exit(EXIT_FAILURE);
    }

    fprintf(stderr, "[-] Merging Global C: A(c_%d_%d_%d_%d, ", a_outer_iter_num, a_inner_iter_num, a_global_rnum, a_global_cnum);
    snprintf(buf, 128, "%s/global/c_%d_%d_%d_%d.new", a_path, a_outer_iter_num, a_inner_iter_num, a_global_rnum, a_global_cnum);
    if((fp = fopen(buf, "r"))==NULL) {
        perror("a_global_c fopen()");
        exit(EXIT_FAILURE);
    }
    n = 0;
    index = 0;
    while ((c = fgetc(fp))!=EOF) {
        if (c==',' || c=='\n') {
            a_global_c[index] = n;
            n = 0;
            index++;
        }
        else {
            n = n*10 + (c-48);
        }
    }
    fclose(fp);

    cnt = 0;
    for(j=0; j<FP_SIZE*8; j++) {
        if(a_global_c[j]<a_global_cnum-1)
            cnt++;        
    }
    fprintf(stderr, "%d cols)", cnt);

    fprintf(stderr, " & B(c_%d_%d_%d_%d, ", b_outer_iter_num, b_inner_iter_num, b_global_rnum, b_global_cnum);
    snprintf(buf, 128, "%s/global/c_%d_%d_%d_%d.new", b_path, b_outer_iter_num, b_inner_iter_num, b_global_rnum, b_global_cnum);
    if((fp = fopen(buf, "r"))==NULL) {
        perror("b_global_c fopen()");
        exit(EXIT_FAILURE);
    }
    n = 0;
    index = 0;
    while ((c = fgetc(fp))!=EOF) {
        if (c==',' || c=='\n') {
            b_global_c[index] = n;
            n = 0;
            index++;
        }
        else {
            n = n*10 + (c-48);
        }
    }
    fclose(fp);

    new_global_cnum = 0;
    for(i=0; i<a_global_cnum; i++) {
        index = 0;
        for(j=0; j<FP_SIZE*8; j++) {
            if(a_global_c[j]==i) {
                list_c[index].column = j;
                list_c[index].group = b_global_c[j];
                index++;
            }
        }
        qsort(list_c, index, sizeof(column_t), compare_column);

        new_global_c[list_c[0].column] = new_global_cnum;
        for(j=1; j<index; j++) {
            if (list_c[j-1].group!=list_c[j].group) new_global_cnum++;
            new_global_c[list_c[j].column] = new_global_cnum;
        }
        new_global_cnum++;
    }

    cnt = 0;
    for(j=0; j<FP_SIZE*8; j++) {
        if(new_global_c[j]<new_global_cnum-1)
            cnt++;        
    }
    fprintf(stderr, "%d cols) ...", cnt);

    fprintf(stderr, "done\n");

    free(a_global_c);
    free(b_global_c);
    free(list_c);
}

int main(int argc, char **argv) {
    char *ptr;
    char buf[64];
    DIR *dirp;
    struct dirent *entry;
    int nfiles;
    FILE *fp;

    if (argc!=5) {
        fprintf(stderr, "%s <db_path_a>  <param_a>  <db_path_b>  <param_b>\n", argv[0]);
        exit(1);
    }

    a_path = strdup(argv[1]);
    ptr = strrchr(argv[2], ',');
    a_global_cnum = atoi(ptr+1);
    *ptr = '\0';
    ptr = strrchr(argv[2], ',');
    a_global_rnum = atoi(ptr+1);
    *ptr = '\0';
    ptr = strrchr(argv[2], ',');
    a_inner_iter_num = atoi(ptr+1);
    *ptr = '\0';
    a_outer_iter_num = atoi(argv[2]);

    b_path = strdup(argv[3]);
    ptr = strrchr(argv[4], ',');
    b_global_cnum = atoi(ptr+1);
    *ptr = '\0';
    ptr = strrchr(argv[4], ',');
    b_global_rnum = atoi(ptr+1);
    *ptr = '\0';
    ptr = strrchr(argv[4], ',');
    b_inner_iter_num = atoi(ptr+1);
    *ptr = '\0';
    b_outer_iter_num = atoi(argv[4]);

    nfiles = 0;
    snprintf(buf, 64, "%s/adjlist", a_path);
    dirp = opendir(buf);
    if (dirp != NULL) {
        while ((entry = readdir(dirp))) {
            if(strcmp(entry->d_name, ".")==0 || strcmp(entry->d_name, "..")==0)
                continue;
            if (entry->d_type & DT_REG)
                nfiles += 1;
        }
        closedir(dirp);
    }
    else {
        perror("adjlist is missing!");
        exit(EXIT_FAILURE);
    }

    snprintf(buf, 64, "%s/adjlist/data0", a_path);
    if((fp=fopen(buf, "r"))==NULL) {
        perror("data fopen()");
        exit(EXIT_FAILURE);
    }
    fseek(fp, 0L, SEEK_END);
    fp_per_file = ftell(fp)/FP_SIZE;
    fclose(fp);
    nsamples = nfiles*fp_per_file;

    if((new_global_r=(int *)malloc(nsamples*sizeof(int)))==NULL) {
        perror("new_global_r malloc()");
        exit(EXIT_FAILURE);
    }
    if((new_global_c=(int *)malloc((FP_SIZE*8)*sizeof(int)))==NULL) {
        perror("new_global_c malloc()");
        exit(EXIT_FAILURE);
    }

    if(access("db.new", F_OK)) 
        mkdir("db.new", S_IRWXU|S_IXGRP|S_IRGRP|S_IROTH|S_IXOTH);
    if(access("db.new/adjlist", F_OK)) 
        mkdir("db.new/adjlist", S_IRWXU|S_IXGRP|S_IRGRP|S_IROTH|S_IXOTH);
    if(access("db.new/global", F_OK)) 
        mkdir("db.new/global", S_IRWXU|S_IXGRP|S_IRGRP|S_IROTH|S_IXOTH);

    merge_global_r();
    merge_global_c();
    output();

    fprintf(stderr, "\n");

    free(new_global_r);
    free(new_global_c);
    free(a_path);
    free(b_path);
}

