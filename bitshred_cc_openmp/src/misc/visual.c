#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <getopt.h>

#define FP_SIZE (1024*32)     // in bytes
//#define FP_SIZE (1024*8)     // in bytes
#define DB_PATH "./db"
    
int outer_iter_num;
int inner_iter_num;
int global_rnum;
int global_cnum;
int nsamples;
int fp_per_file;
int *listr;
int *listc;
int *iter_split;
int iter_split_num;
int is_suffix_new;

void output(char *db_path) {
    int i,j;
    FILE **fp;
    FILE *fpx;
    FILE *fpg;
    FILE *tmp_fp;
    char buf[128];
    char *bf;
    char bitMask;
    int byteIndex;
    int samplenumber;
    int filenumber;
    int prevfilenumber = -1;
    size_t offset;
    int colnumber;
    int total = nsamples+global_rnum-1;
    int rgroup;
    int iter_idx;

    if((fp = (FILE **)malloc(sizeof(FILE *)*(iter_split_num+1)))==NULL) {
        perror("fp malloc()");
        exit(EXIT_FAILURE);
    }
    for(i=0; i<=iter_split_num; i++) {
        snprintf(buf, 128, "%s/matrix%05d.dat", db_path, i);
        if((fp[i] = fopen(buf, "w"))==NULL) {
            perror("matrix.dat fopen()");
            exit(EXIT_FAILURE);
        }
    }
    snprintf(buf, 128, "%s/splitline.dat", db_path);
    if((fpx = fopen(buf, "w"))==NULL) {
        perror("splitline.dat fopen()");
        exit(EXIT_FAILURE);
    }
    if((bf = (char *)malloc((size_t)FP_SIZE*nsamples))==NULL) {
        perror("bf malloc()");
        exit(EXIT_FAILURE);
    }

    fprintf(stderr, "[-] Loading Fingerprints...\n");
    for(i=0; i<nsamples/fp_per_file; i++) {
        snprintf(buf, 128, "%s/adjlist/data%d", db_path, i);
        if((tmp_fp = fopen(buf, "r"))==NULL) {
            perror("adjlist data fopen()");
            exit(EXIT_FAILURE);
        }
        fread(bf+(FP_SIZE*fp_per_file)*i, FP_SIZE*fp_per_file, 1, tmp_fp);
        fclose(tmp_fp);
    }

    fprintf(stderr, "[-] Outputting...    ");
    rgroup = 0;
    iter_idx = 0;
    for(i=0; i<nsamples+global_rnum-1; i++) {
        if(i%100==0) {
            fprintf(stderr, "\b\b\b\b%3.0f%%", i/(total*0.01));
        }
        if (listr[i]==-1) {
            rgroup++;
            if(rgroup==iter_split[iter_idx]) iter_idx++;
            for(j=0; j<FP_SIZE*8+global_cnum-1; j++) {
                fprintf(fpx, "%d\t%d\n", j, (nsamples+global_rnum-1)-i);
            }
            continue;
        }
        else {
            samplenumber = listr[i];
            offset = samplenumber*(size_t)FP_SIZE;
        }
        for(j=0; j<FP_SIZE*8+global_cnum-1; j++) {
            if (listc[j]==-1) {
                fprintf(fpx, "%d\t%d\n", j, (nsamples+global_rnum-1)-i);
            }
            else {
                colnumber = listc[j];
                bitMask = 1 << (colnumber & 0x07);
                byteIndex = colnumber >> 3;
                if(bf[offset+byteIndex] & bitMask) {
                    fprintf(fp[iter_idx], "%d\t%d\n", j, (nsamples+global_rnum-1)-i);
                }
            }
        }
    }
    free(bf);
    for(i=0; i<=iter_split_num;i++) fclose(fp[i]);
    fclose(fpx);

    snprintf(buf, 128, "%s/matrix.p", db_path);
    if((fpg = fopen(buf, "w"))==NULL) {
        perror("matrix.p fopen()");
        exit(EXIT_FAILURE);
    }
    fprintf(fpg, "set term png size %d, %d\n", FP_SIZE*8+global_cnum-1, nsamples+global_rnum-1);
    fprintf(fpg, "set output \"matrix.png\"\n");
    fprintf(fpg, "set bmargin 0\n");
    fprintf(fpg, "set tmargin 0\n");
    fprintf(fpg, "set rmargin 0\n");
    fprintf(fpg, "set lmargin 0\n");
    fprintf(fpg, "set border 0\n");
    fprintf(fpg, "unset xtics\n");
    fprintf(fpg, "unset ytics\n");
    fprintf(fpg, "plot \\\n");
    for(i=0; i<=iter_split_num;i++) {
        if (i%2==0)
            fprintf(fpg, "\t\"matrix%05d.dat\" using 1:2 title \"\" with points pt 5 pointsize 0.1 lc rgb \"#333333\" ,\\\n", i);
        else 
            fprintf(fpg, "\t\"matrix%05d.dat\" using 1:2 title \"\" with points pt 5 pointsize 0.1 lc rgb \"#6666FF\" ,\\\n", i);
    }
    fprintf(fpg,"\t\"splitline.dat\" using 1:2 title \"\" with points pt 5 pointsize 0.1 lc rgb \"#FF6666\"\n");
    fclose(fpg);
}

void get_global_r(char *db_path) {
    int *global_r;
    int n, c, index;
    FILE *fp;
    char buf[128];
    int i, j;

    if((global_r = (int *)malloc(nsamples*sizeof(int)))==NULL) {
        perror("global_r malloc()");
        exit(EXIT_FAILURE);
    }

    fprintf(stderr, "[-] Loading Global R (r_%d_%d_%d_%d)...\n", outer_iter_num, inner_iter_num, global_rnum, global_cnum);
    if (is_suffix_new)
        snprintf(buf, 128, "%s/global/r_%d_%d_%d_%d.new", db_path, outer_iter_num, inner_iter_num, global_rnum, global_cnum);
    else
        snprintf(buf, 128, "%s/global/r_%d_%d_%d_%d", db_path, outer_iter_num, inner_iter_num, global_rnum, global_cnum);

    if((fp = fopen(buf, "r"))==NULL) {
        perror("global_r fopen()");
        exit(EXIT_FAILURE);
    }
    n = 0;
    index = 0;
    while ((c = fgetc(fp))!=EOF) {
        if (c==',' || c=='\n') {
            global_r[index] = n;
            n = 0;
            index++;
        }
        else {
            n = n*10 + (c-48);
        }
    }
    fclose(fp);

    fprintf(stderr, "[-] Arranging Rows...\n");
    index = 0;
    for(i=0; i<global_rnum; i++) {
        for(j=0; j<nsamples; j++) {
            if(global_r[j]==i) {
                listr[index++] = j;
            }
        }
        listr[index++] = -1;
    }
    free(global_r);
}

void get_global_c(char *db_path) {
    int *global_c;
    int n, c, index;
    FILE *fp;
    char buf[128];
    int i,j;
    
    if((global_c = (int *)malloc(FP_SIZE*8*sizeof(int)))==NULL) {
        perror("global_c malloc()");
        exit(EXIT_FAILURE);
    }

    fprintf(stderr, "[-] Loading Global C (c_%d_%d_%d_%d)...\n", outer_iter_num, inner_iter_num, global_rnum, global_cnum);
    if(is_suffix_new)
        snprintf(buf, 128, "%s/global/c_%d_%d_%d_%d.new", db_path, outer_iter_num, inner_iter_num, global_rnum, global_cnum);
    else
        snprintf(buf, 128, "%s/global/c_%d_%d_%d_%d", db_path, outer_iter_num, inner_iter_num, global_rnum, global_cnum);

    if((fp = fopen(buf, "r"))==NULL) {
        perror("global_c fopen()");
        exit(EXIT_FAILURE);
    }
    n = 0;
    index = 0;
    while ((c = fgetc(fp))!=EOF) {
        if (c==',' || c=='\n') {
            global_c[index] = n;
            n = 0;
            index++;
        }
        else {
            n = n*10 + (c-48);
        }
    }
    fclose(fp);

    fprintf(stderr, "[-] Arranging Columns...\n");
    index = 0;
    for(i=0; i<global_cnum; i++) {
        for(j=0; j<FP_SIZE*8; j++) {
            if(global_c[j]==i) {
                listc[index++] = j;
            }
        }
        listc[index++] = -1;
    }
    free(global_c);
}

void usage(void)
{
    fprintf(stderr, "Usage: visual [OPTION...]\n");
    fprintf(stderr, " -h, --help   = show this help\n");
    fprintf(stderr, " -d, --db     = set db path\n");
    fprintf(stderr, " -g, --global = choose a co-clustering result (outer_iter,inner_iter,row_group,col_group)\n");
    fprintf(stderr, " -n, --new    = if a co-clustering result is \"new\" permutation\n\n");
}

int main(int argc, char **argv) {
    int c;
    char *db_path = NULL;
    char *ptr;
    DIR *dirp;
    struct dirent *entry;
    int nfiles;
    FILE *fp;
    char buf[128];

    struct option long_options[] = {
        {"help",    no_argument,        0,  'h'},
        {"db",      required_argument,  0,  'd'},
        {"global",  required_argument,  0,  'g'},
        {"new",     no_argument,        0,  'n'},
        {0,0,0,0}
    };
    int option_index = 0;

    if (argc == 1) {
        usage();
        return -1;
    }

    is_suffix_new = 0;
    opterr = 0;
    while ((c=getopt_long(argc, argv, "hd:g:n", long_options, &option_index)) != -1)
        switch (c) {
            case 'd':
                db_path = strdup(optarg);
                break;
            case 'g':
                ptr = strrchr(optarg, ',');
                global_cnum = atoi(ptr+1);
                *ptr = '\0';
                ptr = strrchr(optarg, ',');
                global_rnum = atoi(ptr+1);
                *ptr = '\0';
                ptr = strrchr(optarg, ',');
                inner_iter_num = atoi(ptr+1);
                *ptr = '\0';
                outer_iter_num = atoi(optarg);
                break;
            case 'n':
                is_suffix_new = 1;
                break;
            case 'h':
            default:
                usage();
                return -1;
        }

    if(optind < argc) {
        usage();
        return -1;
    }

    if(db_path==NULL) 
        db_path = strdup(DB_PATH);

    nfiles = 0;
    snprintf(buf, 128, "%s/adjlist", db_path); 
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

    snprintf(buf, 128, "%s/adjlist/data0", db_path);
    if((fp=fopen(buf, "r"))==NULL) {
        perror("data0 fopen()");
        exit(EXIT_FAILURE);
    }
    fseek(fp, 0L, SEEK_END);
    fp_per_file = ftell(fp)/FP_SIZE;
    fclose(fp);
    nsamples = nfiles*fp_per_file;

    if((listr=(int *)malloc((size_t)(nsamples+global_rnum-1)*sizeof(int)))==NULL) {
        perror("listr malloc()");
        exit(EXIT_FAILURE);
    }
    if((listc = (int *)malloc((size_t)(FP_SIZE*8+global_cnum-1)*sizeof(int)))==NULL) {
        perror("listc malloc()");
        exit(EXIT_FAILURE);
    }
    if((iter_split = (int *)malloc((size_t)(global_rnum-1)*sizeof(int)))==NULL) {
        perror("iter_split malloc()");
        exit(EXIT_FAILURE);
    }

    iter_split_num = 0;
    if((fp=fopen("iter_split.log", "r"))!=NULL) {
        while(fgets(buf, 32, fp)) {
            iter_split[iter_split_num++] = atoi(buf);
        }
        fclose(fp);
    }

    get_global_r(db_path);
    get_global_c(db_path);
    output(db_path);

    fprintf(stderr, "\n");
    if(db_path) free(db_path);
    if(listr) free(listr);
    if(listc) free(listc);
    if(iter_split) free(iter_split);
}

