#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>

#include "vdb.h"
#include "jaccard.h"
#include "bs_common.h"

#define DB_PATH "./db"

/* Global Variables */
unsigned int shredsize = SHRED_SIZE; 
unsigned int windowsize = WINDOW_SIZE; 
unsigned int limit = VIRUS_COUNT;
double threshold = JACCARD_THRESHOLD;

#define EXE_UPDATE          0
#define EXE_COMPARE         1
#define EXE_CLUSTER         2

/* Display the help message */
void usage(void)
{
    bs_msg("Usage: bitshred [OPTION...]\n");
    bs_msg(" -h, --help        = show this help\n\n");
    bs_msg(" -d, --db          = set db path\n");
    bs_msg(" -u, --update      = update database from log file\n");
    bs_msg(" -p, --compare     = compare samples in database\n");
    bs_msg(" -r, --cluster     = cluster samples in database\n");
    bs_msg(" -t, --threshold   = set jaccard threshold value (default: %0.3f)\n", threshold);
    bs_msg(" -l, --limit       = set maximum # of processing files\n");
    bs_msg(" -s, --size        = set shred size (default: %u)\n", shredsize);
    bs_msg(" -w, --window      = set window size (default: %u)\n", windowsize);
    bs_msg(" --debug           = show all error messages\n");
    bs_msg(" -o, --output      = set output file\n");
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
            }
        }
        closedir(dirp);
        return 0;
    }
    else
        return -1;
}

/* Update Virus Database */
void update_database(char *db_path, char *sample_path, unsigned int limit) {
    int i;
    FILE *fp = NULL;
    char buf[64];
    sample_t *sample_list = NULL;
    int nsamples = 0;
    struct timeval t_stime, t_etime;
    double sec_elapsed = 0;

    sprintf(buf, "%s", db_path);
    if(access(buf, F_OK)) 
        mkdir(buf, S_IRWXU|S_IXGRP|S_IRGRP|S_IROTH|S_IXOTH);
    gettimeofday(&t_stime, NULL);

    read_sampledir(sample_path, &sample_list, &nsamples);

    sprintf(buf, "%s/vdb", db_path);
    if(access(buf, F_OK)) 
        mkdir(buf, S_IRWXU|S_IXGRP|S_IRGRP|S_IROTH|S_IXOTH);
    update_vdb(db_path, sample_list, nsamples);

    bs_verbosemsg("Writing to vdb...\n");
    sprintf(buf, "%s/vdb_list", db_path);
    if((fp = fopen(buf, "w")) == NULL){
        perror("vdb_list fopen()");
        exit(EXIT_FAILURE);
    }
    for(i=0; i<nsamples; i++)
        fprintf(fp, "%d\t%s\n", sample_list[i].sample_id, sample_list[i].sample_path);
    fclose(fp);
    free(sample_list);

    sprintf(buf, "%s/vdb_nsamples", db_path);
    if((fp = fopen(buf, "w")) == NULL) {
        perror("vdb_nsamples fopen()");
        exit(EXIT_FAILURE);
    }
    fprintf(fp, "%d", nsamples);
    fclose(fp);

    gettimeofday(&t_etime, NULL);
    sec_elapsed = time_diff(t_etime, t_stime);

    bs_msg("Time: %umin %.3fsec\n\n"
           ,((unsigned int)sec_elapsed / 60), 
           ((sec_elapsed-(unsigned int)sec_elapsed)+(unsigned int)sec_elapsed%60)
           );
}

/* Comparing every pair of samples in database */
void compare_database(char *db_path) {
    FILE *fp;
    char buf[64];
    int nsamples;
    struct timeval t_stime, t_etime;
    double sec_elapsed = 0;

    gettimeofday(&t_stime, NULL);
    
    sprintf(buf, "%s/vdb_nsamples", db_path);
    if((fp = fopen(buf, "r")) == NULL) {
        perror("vdb_nsamples fopen()");
        exit(EXIT_FAILURE);
    }
    if((fgets(buf, 64, fp)) == NULL) {
        perror("reading vdb_nsamples");
        exit(EXIT_FAILURE);
    }
    nsamples = atoi(buf);
    fclose(fp);

    compare_vdb(db_path, nsamples);

    gettimeofday(&t_etime, NULL);
    sec_elapsed = time_diff(t_etime, t_stime);

    bs_verbosemsg("Time: %umin %.3fsec\n\n"
           ,((unsigned int)sec_elapsed / 60), 
           ((sec_elapsed-(unsigned int)sec_elapsed)+(unsigned int)sec_elapsed%60)
           );
}

/* Cluster Databae */
void cluster_database(char *db_path) {
    FILE *fp;
    unsigned int ncluster = 0;
    char buf[64];
    int nsamples;
    sample_t *jdb_list = NULL;
    int njdb = 0;
    struct timeval t_stime, t_etime;
    double sec_elapsed = 0;

    gettimeofday(&t_stime, NULL);

    sprintf(buf, "%s/vdb_nsamples", db_path);
    if((fp = fopen(buf, "r")) == NULL) {
        perror("vdb_namples fopen()");
        exit(EXIT_FAILURE);
    }
    if((fgets(buf, 64, fp)) == NULL) {
        perror("reading vdb_nsamples");
        exit(EXIT_FAILURE);
    }
    nsamples = atoi(buf);
    fclose(fp);

    sprintf(buf, "%s/jdb", db_path);
    read_sampledir(buf, &jdb_list, &njdb);

    ncluster = cluster_vdb(db_path, nsamples, jdb_list, njdb);
    free(jdb_list);

    gettimeofday(&t_etime, NULL);
    sec_elapsed = time_diff(t_etime, t_stime);

    bs_verbosemsg("Time: %umin %.3fsec\n\n"
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

    struct option long_options[] = {
        {"help",        no_argument,            0,      'h'},
        {"db",          required_argument,      0,      'd'},
        {"update",      required_argument,      0,      'u'},
        {"compare",     no_argument,            0,      'p'},
        {"cluster",     no_argument,            0,      'r'},
        {"threshold",   required_argument,      0,      't'},
        {"limit",       required_argument,      0,      'l'},
        {"size",        required_argument,      0,      's'},
        {"window",      required_argument,      0,      'w'},
        {"debug",       no_argument,            0,      'z'},
        {"output",      required_argument,      0,      'o'},
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
    while ((c = getopt_long(argc, argv, "hd:u:prt:l:s:w:zo:", long_options, &option_index)) != -1)
        switch (c) {
            case 'd':
                db_path = strdup(optarg);
                break;
            case 'u':
                sample_path = strdup(optarg);
                exe_inst = EXE_UPDATE;
                break;
            case 'p':
                exe_inst = EXE_COMPARE;
                break;
            case 'r':
                exe_inst = EXE_CLUSTER;
                break;
            case 't':
                threshold = atof(optarg);
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
            case '?':
                if (optopt == 't' || optopt == 'l' || optopt == 's' || optopt == 'w')
                    bs_msg("Missing argument value for -%c option!\n", optopt);
                else if (optopt == 'd' || optopt == 'u' || optopt == 'o')
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
        case EXE_UPDATE:
            if(sample_path == NULL){
                bs_msg("Incorrect options.\n");
                return -1;
            }
            if(db_path == NULL)
                db_path = strdup(DB_PATH);

            update_database(db_path, sample_path, limit);
            break;

        case EXE_COMPARE:
            if(db_path == NULL)
                db_path = strdup(DB_PATH);

            compare_database(db_path);
            break;
            
        case EXE_CLUSTER:
            if(db_path == NULL)
                db_path = strdup(DB_PATH);

            cluster_database(db_path);
            break;

        default:
            return -1;
    }

    if(db_path) free(db_path);
    if(sample_path) free(sample_path);
    if(out_file) fclose(stdout);
    return 0;
}
