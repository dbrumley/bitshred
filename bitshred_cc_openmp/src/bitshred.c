#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>

#include "bs_common.h"

#define DB_PATH "./db"

/* global variables */
unsigned int shredsize = SHRED_SIZE; 
unsigned int windowsize = WINDOW_SIZE; 
unsigned int limit = VIRUS_COUNT;
int row_max_threads = ROW_MAX_THREADS;
int col_max_threads = COL_MAX_THREADS;

int nsamples;
bitshred_t *bs_fp = NULL;
uint64_t *global_g = NULL;
unsigned int *global_r = NULL;
unsigned int *global_c = NULL;
unsigned int global_rnum = 0;
unsigned int global_cnum = 0;
unsigned int *rows_in_each_group = NULL;
unsigned int *cols_in_each_group = NULL;
uint64_t *prev_global_g = NULL;
unsigned int *prev_global_r = NULL;
unsigned int *prev_global_c = NULL;
unsigned int prev_global_rnum;
unsigned int prev_global_cnum;
unsigned int *prev_rows_in_each_group = NULL;
unsigned int *prev_cols_in_each_group = NULL;

#define EXE_CCSAMPLES   0
#define EXE_CCDATA      1
#define EXE_CCDUMP      2
#define EXE_CCPERMUTE   3

/* Display the help message */
void usage(void)
{
    bs_msg("Usage: bitshred [OPTION...]\n");
    bs_msg(" -h, --help        = show this help\n\n");
    bs_msg(" -d, --db          = set db path\n");
    bs_msg(" -m, --malware     = run coclustering on malware samples\n");
    bs_msg(" -t, --data        = run coclustering on pre-built data\n");
    bs_msg(" -r, --row         = set initial # of row groups\n");
    bs_msg(" -c, --column      = set initial # of column groups\n");
    bs_msg(" -a, --rowmax      = set # of threads for row iterations\n");
    bs_msg(" -b, --colmax      = set # of threads for column iterations\n");
    bs_msg(" -l, --limit       = set maximum # of processing files\n");
    bs_msg(" -s, --size        = set shred size (default: %u)\n", shredsize);
    bs_msg(" -w, --window      = set window size (default: %u)\n", windowsize);
    bs_msg(" --debug           = show all error messages\n");
    bs_msg(" -o, --output      = set output file\n");
    bs_msg(" -u, --dump        = dump fingerprints in ASCII\n");
    bs_msg(" -p, --permute     = permute coclustering results\n\n");
}

int read_sampledir(char *cur_dir, sample_t **sample_list, int *nsamples) {
    DIR *dirp;
    struct dirent *entry;
    char sub_dir[1024];

    dirp = opendir(cur_dir);
    if (dirp != NULL) {
        while ((entry = readdir(dirp))) {
            if(strcmp(entry->d_name, ".")==0 || strcmp(entry->d_name, "..")==0)
                continue;

            if (entry->d_type & DT_DIR) {
                snprintf(sub_dir, 1024, "%s/%s", cur_dir, entry->d_name);
                read_sampledir(sub_dir, sample_list, nsamples);
            }
            else {
                if((*nsamples)%128 == 0) {
                    if((*sample_list = (sample_t *)realloc(*sample_list, sizeof(sample_t)*((*nsamples)+128))) == NULL) {
                        perror("samples_list realloc()");
                        exit(EXIT_FAILURE);
                    }
                }
                //(*sample_list)[(*nsamples)].sample_id = *nsamples;
                snprintf((*sample_list)[(*nsamples)].sample_path, 256, "%s/%s", cur_dir, entry->d_name);
                *nsamples += 1;
                if (*nsamples==limit) return 0;
            }
        }
        closedir(dirp);
        return 0;
    }
    else
        return -1;
}

void ccrun(char *db_path) {
    int inner_iter_num;
    int outer_iter_num;
    double cost;
    double prev_inner_cost;
    double prev_outer_cost;
    int is_row_failed = 0;
    int is_col_failed = 0;
    int is_doubling_failed = 0;
    int split_group = ROW_SPLIT;
    int num_split;
    int i;

    if((global_g = (uint64_t *)malloc(sizeof(uint64_t)*global_cnum*global_rnum))==NULL) {
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
    ccinit();

    //outer loop
    prev_inner_cost = 0;
    prev_outer_cost = 0;
    outer_iter_num = 0;
    num_split = 1;
    while (1) {
        outer_iter_num++;

        //inner loop
        inner_iter_num = 0;
        bs_output(db_path, outer_iter_num, inner_iter_num);
        while (1) {
            inner_iter_num++;
            for(i=0; i<inner_iter_num; i++) bs_msg(" ");
            ccrow(outer_iter_num, inner_iter_num);          //perform row iteration
            for(i=0; i<inner_iter_num; i++) bs_msg(" ");
            cccol(outer_iter_num, inner_iter_num);          //perform column iteration
            for(i=0; i<inner_iter_num; i++) bs_msg(" ");
            cost = cccost(outer_iter_num, inner_iter_num);  //calculate cost

            if (inner_iter_num==1) {
                prev_inner_cost = cost;
            }
            else {
                if (cost < prev_inner_cost*INNER_COST_THRESHOLD)
                    prev_inner_cost = cost;
                else
                    break;
            }
        }
        bs_output(db_path, outer_iter_num, inner_iter_num);
        bs_msg("\n");
        fflush(stdout);

        // TODO : num_split
        if (outer_iter_num==1) {
            if (prev_global_g) free(prev_global_g);
            if (prev_global_r) free(prev_global_r);
            if (prev_global_c) free(prev_global_c);
            if (prev_rows_in_each_group) free(prev_rows_in_each_group);
            if (prev_cols_in_each_group) free(prev_cols_in_each_group);

            prev_global_g = global_g;
            prev_global_r = global_r;
            prev_global_c = global_c;
            prev_rows_in_each_group = rows_in_each_group;
            prev_cols_in_each_group = cols_in_each_group;
            prev_global_rnum = global_rnum;
            prev_global_cnum = global_cnum;

            prev_outer_cost = cost;
            split_group = ROW_SPLIT;
            global_rnum += num_split;
            //global_rnum++;
        }
        else {
            if (cost < prev_outer_cost*OUTER_COST_THRESHOLD) {
                if (prev_global_g) free(prev_global_g);
                if (prev_global_r) free(prev_global_r);
                if (prev_global_c) free(prev_global_c);
                if (prev_rows_in_each_group) free(prev_rows_in_each_group);
                if (prev_cols_in_each_group) free(prev_cols_in_each_group);

                prev_global_g = global_g;
                prev_global_r = global_r;
                prev_global_c = global_c;
                prev_rows_in_each_group = rows_in_each_group;
                prev_cols_in_each_group = cols_in_each_group;
                prev_global_rnum = global_rnum;
                prev_global_cnum = global_cnum;

                prev_outer_cost = cost;

                if (split_group==ROW_SPLIT) {
                    if(!is_doubling_failed && 2*num_split<=global_rnum) 
                        num_split *= 2;

                    is_col_failed = 0;
                    split_group = ROW_SPLIT;
                    global_rnum += num_split;
                    //global_rnum++;
                }
                else {
                    if(!is_doubling_failed && 2*num_split<=global_cnum) 
                        num_split *= 2;

                    is_row_failed = 0;
                    split_group = COL_SPLIT;
                    global_cnum += num_split;
                    //global_cnum++;
                }
            }
            else {
                if (global_g) free(global_g);
                if (global_r) free(global_r);
                if (global_c) free(global_c);
                if (rows_in_each_group) free(rows_in_each_group);
                if (cols_in_each_group) free(cols_in_each_group);

                if(num_split==1) {
                    is_doubling_failed = 0;
                    if (split_group==ROW_SPLIT) {
                        is_row_failed = 1;
                        if (is_col_failed) break;
                        else {
                            split_group = COL_SPLIT;
                            global_rnum = prev_global_rnum;
                            global_cnum = prev_global_cnum+1;
                        }
                    }
                    else {
                        is_col_failed = 1;
                        if (is_row_failed) break;
                        else {
                            split_group = ROW_SPLIT;
                            global_rnum = prev_global_rnum+1;
                            global_cnum = prev_global_cnum;
                        }
                    }
                }
                else {
                    is_doubling_failed = 1;
                    num_split /= 2;
                    if (split_group==ROW_SPLIT) {
                        global_rnum = prev_global_rnum+num_split;
                        global_cnum = prev_global_cnum;
                    }
                    else {
                        global_rnum = prev_global_rnum;
                        global_cnum = prev_global_cnum+num_split;
                    }
                }
            }
        }
        ccsplit(split_group, num_split);       //split the group with the highest cost
    }

    bs_msg("[] %d row / %d col: %.2f (Please search this cost value.)\n", prev_global_rnum, prev_global_cnum, prev_outer_cost);

//    if (global_g) free(global_g);
//    if (global_r) free(global_r);
//    if (global_c) free(global_c);
//    if (rows_in_each_group) free(rows_in_each_group);
//    if (cols_in_each_group) free(cols_in_each_group);
    if (prev_global_g) free(prev_global_g);
    if (prev_global_r) free(prev_global_r);
    if (prev_global_c) free(prev_global_c);
    if (prev_rows_in_each_group) free(prev_rows_in_each_group);
    if (prev_cols_in_each_group) free(prev_cols_in_each_group);
}

int compare_filename(const void *a, const void *b) {
//    char *ptr;
//    ptr = strrchr(((sample_t *)a)->sample_path, 'a');
//    int p = atoi(ptr+1);
//    ptr = strrchr(((sample_t *)b)->sample_path, 'a');
//    int q = atoi(ptr+1);
//    return p-q;
    return strcmp(((sample_t *)a)->sample_path, ((sample_t *)b)->sample_path);
}

void ccdata(char *db_path, char *sample_path) {
    char buf[64];
    sample_t *sample_list = NULL;
    int cnt = 0;
    FILE *fp;
    int fp_per_file;
    struct timeval t_stime, t_etime;
    double sec_elapsed = 0;

    gettimeofday(&t_stime, NULL);

    read_sampledir(sample_path, &sample_list, &cnt);
    qsort(sample_list, cnt, sizeof(sample_t), compare_filename);
    if((fp=fopen(sample_list[0].sample_path, "r"))==NULL) {
        perror("data fopen()");
        exit(EXIT_FAILURE);
    }
    fseek(fp, 0L, SEEK_END);
    fp_per_file = ftell(fp)/FP_SIZE;
    fclose(fp);
    nsamples = cnt*fp_per_file;

    sprintf(buf, "%s", db_path);
    if(access(buf, F_OK)) 
        mkdir(buf, S_IRWXU|S_IXGRP|S_IRGRP|S_IROTH|S_IXOTH);
    sprintf(buf, "%s/adjlist", db_path);
    if(access(buf, F_OK)) 
        mkdir(buf, S_IRWXU|S_IXGRP|S_IRGRP|S_IROTH|S_IXOTH);
    sprintf(buf, "%s/global", db_path);
    if(access(buf, F_OK)) 
        mkdir(buf, S_IRWXU|S_IXGRP|S_IRGRP|S_IROTH|S_IXOTH);

    if((bs_fp = (bitshred_t *)malloc(sizeof(bitshred_t)*nsamples)) == NULL){
        perror("bs_fp malloc()");
        exit(EXIT_FAILURE);
    }

    if (nsamples%row_max_threads!=0) row_max_threads = 1;
    if ((FP_SIZE*8)%col_max_threads!=0) col_max_threads = 1;

    ccread(db_path, sample_list, fp_per_file);      //read pre-built adjacent lists
    free(sample_list);

    /*
    int i, j;
    unsigned int k;
    unsigned int setbits = 0;
    for(i=0; i<FP_SIZE/4; i++) {
        k = 0;
        for(j=0; j<nsamples; j++) {
            k = k | ((unsigned int*)(bs_fp+j)->bit_vector)[i];
        }
        setbits += bitcount(k);
    }
    fprintf(stderr, "[] # of zero columns: %u\n", FP_SIZE*8-setbits);
    return;
    */

    ccrun(db_path);
    free(bs_fp);
    
    gettimeofday(&t_etime, NULL);
    sec_elapsed = time_diff(t_etime, t_stime);
    bs_msg("Time: %umin %.3fsec\n\n"
           ,((unsigned int)sec_elapsed / 60), 
           ((sec_elapsed-(unsigned int)sec_elapsed)+(unsigned int)sec_elapsed%60)
           );
}

void ccsamples(char *db_path, char *sample_path) {
    char buf[64];
    sample_t *sample_list = NULL;
    int cnt = 0;
    struct timeval t_stime, t_etime;
    double sec_elapsed = 0;

    gettimeofday(&t_stime, NULL);

    read_sampledir(sample_path, &sample_list, &cnt);
    nsamples = cnt;

    sprintf(buf, "%s", db_path);
    if(access(buf, F_OK)) 
        mkdir(buf, S_IRWXU|S_IXGRP|S_IRGRP|S_IROTH|S_IXOTH);
    sprintf(buf, "%s/adjlist", db_path);
    if(access(buf, F_OK)) 
        mkdir(buf, S_IRWXU|S_IXGRP|S_IRGRP|S_IROTH|S_IXOTH);
    sprintf(buf, "%s/global", db_path);
    if(access(buf, F_OK)) 
        mkdir(buf, S_IRWXU|S_IXGRP|S_IRGRP|S_IROTH|S_IXOTH);

    if((bs_fp = (bitshred_t *)malloc(sizeof(bitshred_t)*nsamples)) == NULL){
        perror("bs_fp malloc()");
        exit(EXIT_FAILURE);
    }

    if (nsamples%row_max_threads!=0) row_max_threads = 1;
    if ((FP_SIZE*8)%col_max_threads!=0) col_max_threads = 1;

    ccgen(db_path, sample_list);        //generate fingerprints
    free(sample_list);

    ccrun(db_path);
    free(bs_fp);
    
    gettimeofday(&t_etime, NULL);
    sec_elapsed = time_diff(t_etime, t_stime);
    bs_msg("Time: %umin %.3fsec\n\n"
           ,((unsigned int)sec_elapsed / 60), 
           ((sec_elapsed-(unsigned int)sec_elapsed)+(unsigned int)sec_elapsed%60)
           );
}

void ccdump(char *db_path, char *sample_path) {
    char buf[64];
    sample_t *sample_list = NULL;
    int cnt = 0;
    struct timeval t_stime, t_etime;
    double sec_elapsed = 0;

    gettimeofday(&t_stime, NULL);

    read_sampledir(sample_path, &sample_list, &cnt);
    nsamples = cnt;

    sprintf(buf, "%s", db_path);
    if(access(buf, F_OK)) 
        mkdir(buf, S_IRWXU|S_IXGRP|S_IRGRP|S_IROTH|S_IXOTH);
    sprintf(buf, "%s/adjlist", db_path);
    if(access(buf, F_OK)) 
        mkdir(buf, S_IRWXU|S_IXGRP|S_IRGRP|S_IROTH|S_IXOTH);

    if((bs_fp = (bitshred_t *)malloc(sizeof(bitshred_t)*nsamples)) == NULL){
        perror("bs_fp malloc()");
        exit(EXIT_FAILURE);
    }

    if (nsamples%row_max_threads!=0) row_max_threads = 1;
    if ((FP_SIZE*8)%col_max_threads!=0) col_max_threads = 1;

    ccgen_ascii(db_path, sample_list);        //generate fingerprints
    free(sample_list);
    free(bs_fp);
    
    gettimeofday(&t_etime, NULL);
    sec_elapsed = time_diff(t_etime, t_stime);
    bs_msg("Time: %umin %.3fsec\n\n"
           ,((unsigned int)sec_elapsed / 60), 
           ((sec_elapsed-(unsigned int)sec_elapsed)+(unsigned int)sec_elapsed%60)
           );
}

int main(int argc, char **argv) 
{
    int c;
    int exe_inst;
    char *db_path = NULL;
    char *sample_path = NULL;
    char *out_file = NULL;
    char *ptr;
    char *file_path = NULL;
    int outer_iter_num = 0;
    int inner_iter_num = 0;

    struct option long_options[] = {
        {"help",        no_argument,            0,      'h'},
        {"db",          required_argument,      0,      'd'},
        {"malware",     required_argument,      0,      'm'},
        {"data",        required_argument,      0,      't'},
        {"row",         required_argument,      0,      'r'},
        {"column",      required_argument,      0,      'c'},
        {"rowmax",      required_argument,      0,      'a'},
        {"colmax",      required_argument,      0,      'b'},
        {"limit",       required_argument,      0,      'l'},
        {"size",        required_argument,      0,      's'},
        {"window",      required_argument,      0,      'w'},
        {"debug",       no_argument,            0,      'z'},
        {"output",      required_argument,      0,      'o'},
        {"dump",        required_argument,      0,      'u'},
        {"permute",     required_argument,      0,      'p'},
        {0,0,0,0}
    };
    int option_index = 0;

    if (argc == 1) {
        usage();
        return -1;
    }

    umask(0002); // Set file access right
    exe_inst = -1;

    opterr = 0;
    while ((c = getopt_long(argc, argv, "hd:m:t:r:c:a:b:l:s:w:zo:u:p:", long_options, &option_index)) != -1)
        switch (c) {
            case 'd':
                db_path = strdup(optarg);
                break;
            case 'm':
                sample_path = strdup(optarg);
                exe_inst = EXE_CCSAMPLES;
                break;
            case 't':
                sample_path = strdup(optarg);
                exe_inst = EXE_CCDATA;
                break;
            case 'r':
                global_rnum = atoi(optarg);
                break;
            case 'c':
                global_cnum = atoi(optarg);
                break;
            case 'a':
                row_max_threads = atoi(optarg);
                break;
            case 'b':
                col_max_threads = atoi(optarg);
                break;
            case 'l':
                limit = atoi(optarg);
                break;
            case 's':
                shredsize = atoi(optarg);
                break;
            case 'w':
                windowsize = atoi(optarg);
                break;
            case 'z':
                debug_flag = 1;
                break;
            case 'o':
                out_file = strdup(optarg);
                file_path = strdup(out_file);
                ptr = strrchr(file_path, '/');
                if(ptr != NULL) {
                    *ptr = '\0';
                    if(access(file_path, F_OK)) 
                        mkdir(file_path, S_IRWXU|S_IXGRP|S_IRGRP|S_IROTH|S_IXOTH);
                    free(file_path);
                }
                if((freopen(out_file, "w", stdout)) == NULL) {
                    perror("out_file fopen()");
                    exit(EXIT_FAILURE);
                }
                break;
            case 'u':
                sample_path = strdup(optarg);
                exe_inst = EXE_CCDUMP;
                break;
            case 'p':
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
                exe_inst = EXE_CCPERMUTE;
                break;
            case '?':
                if (optopt=='r' || optopt=='c' || optopt=='a' || optopt=='b' || optopt=='l' || optopt=='s' || optopt=='w' || optopt=='p')
                    bs_msg("Missing argument value for -%c option!\n", optopt);
                else if (optopt=='d' || optopt=='m' || optopt=='t' || optopt=='o' || optopt=='u')
                    bs_msg("Missing file name for -%c option!\n", optopt);
                else
                    bs_msg("Unknown option!\n");
                return -1;
            case 'h':
            default:
                usage();
                return -1;
        }

    if(optind < argc){
        usage();
        return -1;
    }

    switch (exe_inst) {
        case EXE_CCSAMPLES:
            if(sample_path==NULL || global_rnum==0 || global_cnum==0){
                bs_msg("Incorrect options.\n");
                return -1;
            }
            if(db_path == NULL)
                db_path = strdup(DB_PATH);

            ccsamples(db_path, sample_path);
            break;

        case EXE_CCDATA:
            if(sample_path==NULL || global_rnum==0 || global_cnum==0){
                bs_msg("Incorrect options.\n");
                return -1;
            }
            if(db_path == NULL)
                db_path = strdup(DB_PATH);

            ccdata(db_path, sample_path);
            break;
        
        case EXE_CCDUMP:
            if(sample_path==NULL){
                bs_msg("Incorrect options.\n");
                return -1;
            }
            if(db_path == NULL)
                db_path = strdup(DB_PATH);

            ccdump(db_path, sample_path);
            break;

        case EXE_CCPERMUTE:
            if(db_path == NULL)
                db_path = strdup(DB_PATH);

            ccpermute(db_path, outer_iter_num, inner_iter_num);
            break;
        default:
            return -1;
    }

    if(db_path) free(db_path);
    if(sample_path) free(sample_path);
    if(out_file) fclose(stdout);
    return 0;
}
