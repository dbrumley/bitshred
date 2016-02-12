#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <db.h>
#include <fts.h>

#include "bs_common.h"
#include "vdb.h"
#include "jaccard.h"
#include "shred.h"

#define DB_PATH "./db"

/* global variables */
unsigned int shredsize  = SHRED_SIZE; 
unsigned int windowsize = WINDOW_SIZE; 
double threshold        = JACCARD_THRESHOLD;

#define EXE_ADD_BIN         0
#define EXE_ADD_TXT         1
#define EXE_COMPARE         2
#define EXE_CLUSTER         3
#define EXE_GETVINFO        4
#define EXE_NEIGHBOR        5

/* display the help message */
void usage(void)
{
    bs_msg("Usage: bitshred [OPTION...]\n");
    bs_msg(" -h, --help        = show this help\n\n");
    bs_msg(" -d, --db          = set database path\n");
    bs_msg(" -b, --binary      = update database by processing binary files\n");
    bs_msg(" -t, --text        = update database by processing text files\n");
    bs_msg(" -p, --compare     = compare samples in database\n");
    bs_msg(" -r, --cluster     = cluster samples in database\n");
    bs_msg(" -n, --neighbor    = find nearesst neighbors in database\n");
    bs_msg(" --vinfo           = show virus info\n\n");
    bs_msg(" -j, --jaccard     = set jaccard threshold value (default: %0.3f)\n", threshold);
    bs_msg(" -s, --size        = set shred size (default: %u)\n", shredsize);
    bs_msg(" -w, --window      = set window size (default: %u)\n", windowsize);
    bs_msg(" --debug           = show all error messages\n");
    bs_msg(" -o, --output      = set output file\n\n");
}

/* update database */
void update_database(char *db_path, char *input_path, int exe_inst) {
    FTS *ftsp;
    FTSENT *p, *chp;
    int fts_options = FTS_NOSTAT | FTS_COMFOLLOW | FTS_PHYSICAL;
    char *target[2];
    DB *dbp;
    int ret;
    bitshred_t *vdb = NULL;
    FILE *fp = NULL;
    int nfile = 0;
    int nvirus = 0;
    int i;
    uint64_t t_filesize = 0;
    uint64_t t_secsize = 0;
    struct timeval t_stime, t_etime;
    double sec_elapsed = 0;
    char buf[64];

    sprintf(buf, "%s", db_path);
    if(access(buf, F_OK))
        mkdir(buf, S_IRWXU|S_IXGRP|S_IRGRP|S_IROTH|S_IXOTH);
    gettimeofday(&t_stime, NULL);

    /* initialize ftsp */
    target[0] = input_path;
    target[1] = NULL;
    if ((ftsp = fts_open(target, fts_options, NULL))==NULL) {
        bs_errmsg("[!] fts_open(): %s\n", input_path);
        exit(EXIT_FAILURE);
    }
    if ((chp = fts_children(ftsp, 0))==NULL) {
        return;   // No files to traverse
    }

    /* open DB */
    if((ret = db_create(&dbp, NULL, 0)) != 0){
        bs_errmsg("[!] db_create(): %s\n", db_strerror(ret));
        exit(EXIT_FAILURE);
    }
    sprintf(buf, "%s/vdb", db_path);
    //if((ret = dbp->open(dbp, NULL, vdb_path, NULL, DB_RECNO, DB_CREATE | DB_TRUNCATE, 0664)) != 0){
    if((ret = dbp->open(dbp, NULL, buf, NULL, DB_RECNO, DB_CREATE, 0664)) != 0){
        dbp->err(dbp, ret, "[!] %s", buf);
        exit(EXIT_FAILURE);
    }

    /* # virus in DB before update */
    sprintf(buf, "%s/vdb_nvir.txt", db_path);
    if(access(buf, F_OK) == 0) {
        if((fp = fopen(buf, "r")) == NULL) {
            bs_errmsg("[!] fopen(): %s\n", buf);
            exit(EXIT_FAILURE);
        }
        if((fgets(buf, 64, fp)) == NULL) {
            bs_errmsg("[!] fgets(): vdb_nvir.txt\n");
            exit(EXIT_FAILURE);
        }
        nvirus = atoi(buf);
        if((fgets(buf, 64, fp)) == NULL) {
            bs_errmsg("[!] fgets(): vdb_nvir.txt\n");
            exit(EXIT_FAILURE);
        }
        nvirus += atoi(buf);
        fclose(fp);
    }
    else {
        nvirus = 0;
    }

    /* list of input files */
    sprintf(buf, "%s/vdb_list.txt", db_path);
    if((fp = fopen(buf, "a")) == NULL) {
        bs_errmsg("[!] fopen(): %s\n", buf);
        exit(EXIT_FAILURE);
    }

    if((vdb = malloc(sizeof(bitshred_t))) == NULL){
        bs_errmsg("[!] malloc(): vdb\n");
        exit(EXIT_FAILURE);
    }

    bs_verbosemsg("[-] Updating database...\n");

    /* traverse input files */
    if (exe_inst==EXE_ADD_BIN) {    // binary files
        while ((p = fts_read(ftsp)) != NULL) {
            switch (p->fts_info) {
            case FTS_F:
            case FTS_NSOK:
                update_vdb_bin(dbp, fp, p->fts_name, vdb, nvirus, &nfile, &t_filesize, &t_secsize);
                break;
            default:
                break;
            }
        }
    }
    else if (exe_inst==EXE_ADD_TXT) {   // text files
        while ((p = fts_read(ftsp)) != NULL) {
            switch (p->fts_info) {
            case FTS_F:
            case FTS_NSOK:
                update_vdb_txt(dbp, fp, p->fts_name, vdb, nvirus, &nfile, &t_filesize, &t_secsize);
                break;
            default:
                break;
            }
        }
    }

    /* close DB */
    dbp->close(dbp, 0);
    fts_close(ftsp);
    free(vdb);
    fclose(fp);

    gettimeofday(&t_etime, NULL);
    sec_elapsed = time_diff(t_etime, t_stime);

    /* # virus in DB after update */
    sprintf(buf, "%s/vdb_nvir.txt", db_path);
    if((fp = fopen(buf, "w")) == NULL) {
        bs_errmsg("[!] fopen(): %s\n", buf);
        exit(EXIT_FAILURE);
    }
    fprintf(fp, "%d\n%d\n", nvirus, nfile);
    fclose(fp);

    /* report statistics */
    if((fp = fopen("/proc/self/status", "r")) == NULL) {
        bs_errmsg("[!] fopen(): /proc/self/status\n");
        exit(EXIT_FAILURE);
    }
    for(i=0; i<11; i++) {
        if((fgets(buf, 64, fp)) == NULL) {
            bs_errmsg("[!] fgets(): /proc/self/status\n");
            exit(EXIT_FAILURE);
        }
    }
    fclose(fp);

    bs_msg("\n--------------- Updating Database ---------------\n"
           "Processed files  : %u\n"
           "File size        : %.2f MiB\n"
           "Section size     : %.2f MiB (executable)\n"
           "Fingerprint size : %.2f MiB (considering only FP size w/o metadata)\n "
           "%s"
           "Time             : %umin %.3fsec\n\n"
           , nfile, 
           (double)t_filesize/(1024*1024), 
           (double)t_secsize/(1024*1024),
           (double)(FP_SIZE*nfile)/(1024*1024),
           buf,
           ((unsigned int)sec_elapsed / 60), 
           ((sec_elapsed-(unsigned int)sec_elapsed)+(unsigned int)sec_elapsed%60)
           );
}

/* compare every pair of samples in database */
void compare_database(const char *db_path) {
    FILE *fp;
    int nvirus, nvirus_added;
    char buf[64];
    unsigned int i;
    unsigned int ncmp = 0;
    struct timeval t_stime, t_etime;
    double sec_elapsed = 0;

    gettimeofday(&t_stime, NULL);
    
    /* # virus in DB */
    sprintf(buf, "%s/vdb_nvir.txt", db_path);
    if((fp = fopen(buf, "r")) == NULL) {
        bs_errmsg("[!] fopen(): %s\n", buf);
        exit(EXIT_FAILURE);
    }
    if((fgets(buf, 64, fp)) == NULL) {
        bs_errmsg("[!] fgets(): vdb_nvir.txt\n");
        exit(EXIT_FAILURE);
    }
    nvirus = atoi(buf);
    if((fgets(buf, 64, fp)) == NULL) {
        bs_errmsg("[!] fgets(): vdb_nvir.txt\n");
        exit(EXIT_FAILURE);
    }
    nvirus_added = atoi(buf);
    fclose(fp);

    bs_verbosemsg("[-] Comparing samples in database...     ");

    compare_vdb(db_path, nvirus, nvirus_added, &ncmp);

    gettimeofday(&t_etime, NULL);
    sec_elapsed = time_diff(t_etime, t_stime);

    /* report statistics */
    if((fp = fopen("/proc/self/status", "r")) == NULL) {
        bs_errmsg("[!] fopen(): /proc/self/status\n");
        exit(EXIT_FAILURE);
    }
    for(i=0; i<11; i++) {
        if((fgets(buf, 64, fp)) == NULL) {
            bs_errmsg("[!] fgets(): /proc/self/status\n");
            exit(EXIT_FAILURE);
        }
    }
    fclose(fp);

    bs_msg("\n---------------- Comparing Database ---------------\n"
           "# of viruses    : %u\n"
           "# of comparison : %u\n"
           "%s"
           "Time            : %umin %.3fsec\n\n"
           , nvirus+nvirus_added, 
           ncmp,
           buf,
           ((unsigned int)sec_elapsed / 60), 
           ((sec_elapsed-(unsigned int)sec_elapsed)+(unsigned int)sec_elapsed%60)
           );
}

/* cluster samples in databae */
void cluster_database(const char *db_path) {
    FILE *fp;
    unsigned int ncluster = 0;
    char buf[64];
    struct timeval t_stime, t_etime;
    double sec_elapsed = 0;
    unsigned int i;
    int nvirus;

    gettimeofday(&t_stime, NULL);

    /* # virus in DB */
    sprintf(buf, "%s/vdb_nvir.txt", db_path);
    if((fp = fopen(buf, "r")) == NULL) {
        bs_errmsg("[!] fopen(): %s\n", buf);
        exit(EXIT_FAILURE);
    }
    if((fgets(buf, 64, fp)) == NULL) {
        bs_errmsg("[!] fgets(): vdb_nvir.txt\n");
        exit(EXIT_FAILURE);
    }
    nvirus = atoi(buf);
    if((fgets(buf, 64, fp)) == NULL) {
        bs_errmsg("[!] fgets(): vdb_nvir.txt\n");
        exit(EXIT_FAILURE);
    }
    nvirus += atoi(buf);
    fclose(fp);

    bs_verbosemsg("[-] Clustering with threshold %.5f ... ", threshold);

    ncluster = cluster_vdb(nvirus, db_path);

    gettimeofday(&t_etime, NULL);
    sec_elapsed = time_diff(t_etime, t_stime);

    /* report statistics */
    if((fp = fopen("/proc/self/status", "r")) == NULL) {
        bs_errmsg("[!] fopen(): /proc/self/status\n");
        exit(EXIT_FAILURE);
    }
    for(i=0; i<11; i++) {
        if((fgets(buf, 64, fp)) == NULL) {
            bs_errmsg("[!] fgets(): /proc/self/status\n");
            exit(EXIT_FAILURE);
        }
    }
    fclose(fp);

    bs_msg("\n--------------- Clustering Database ---------------\n"
           "Jaccard Threshold : %.3f\n"
           "# of clusters     : %u\n"
           "%s"
           "Time              : %umin %.3fsec\n\n"
           , threshold,
           ncluster,
           buf,
           ((unsigned int)sec_elapsed / 60), 
           ((sec_elapsed-(unsigned int)sec_elapsed)+(unsigned int)sec_elapsed%60)
           );
}

/* query nearest neighbors */
void neighbor(char *db_path, char *input_path) {
    FTS *ftsp;
    FTSENT *p, *chp;
    int fts_options = FTS_NOSTAT | FTS_COMFOLLOW | FTS_PHYSICAL;
    char *target[2];
    DB *vdbp;
    int ret;
    bitshred_t *vdb = NULL;
    FILE *fp = NULL;
    int nfile = 0;
    unsigned int ncmp = 0;
    uint64_t t_filesize = 0;
    uint64_t t_secsize = 0;
    struct timeval t_stime, t_etime;
    double sec_elapsed = 0;
    char buf[64];
    int i, nvirus;

    gettimeofday(&t_stime, NULL);

    /* initialize ftsp */
    target[0] = input_path;
    target[1] = NULL;
    if ((ftsp = fts_open(target, fts_options, NULL))==NULL) {
        bs_errmsg("[!] fts_open(): %s\n", input_path);
        exit(EXIT_FAILURE);
    }
    if ((chp = fts_children(ftsp, 0))==NULL) {
        return;   // No files to traverse
    }

    /* open DB */
    if((ret = db_create(&vdbp, NULL, 0)) != 0){
        bs_errmsg("[!] db_create(): %s\n", db_strerror(ret));
        exit(EXIT_FAILURE);
    }
    sprintf(buf, "%s/vdb", db_path);
    if((ret = vdbp->open(vdbp, NULL, buf, NULL, DB_RECNO, DB_RDONLY, 0664)) != 0){
        vdbp->err(vdbp, ret, "[!] %s", buf);
        exit(EXIT_FAILURE);
    }

    /* # virus in DB */
    sprintf(buf, "%s/vdb_nvir.txt", db_path);
    if((fp = fopen(buf, "r")) == NULL) {
        bs_errmsg("[!] fopen(): %s\n", buf);
        exit(EXIT_FAILURE);
    }
    if((fgets(buf, 64, fp)) == NULL) {
        bs_errmsg("[!] fgets(): vdb_nvir.txt\n");
        exit(EXIT_FAILURE);
    }
    nvirus = atoi(buf);
    if((fgets(buf, 64, fp)) == NULL) {
        bs_errmsg("[!] fgets(): vdb_nvir.txt\n");
        exit(EXIT_FAILURE);
    }
    nvirus += atoi(buf);
    fclose(fp);

    if((vdb = malloc(sizeof(bitshred_t))) == NULL){
        bs_errmsg("[!] malloc(): vdb\n");
        exit(EXIT_FAILURE);
    }

    /* list of neighbors found */
    if((fp = fopen("neighbor_list.txt", "w")) == NULL) {
        bs_errmsg("[!] fopen(): neighbor_list.txt\n");
        exit(EXIT_FAILURE);
    }

    while ((p = fts_read(ftsp)) != NULL) {
        switch (p->fts_info) {
        case FTS_F:
        case FTS_NSOK:
            neighbor_vdb(vdbp, fp, p->fts_path, vdb, nvirus, &nfile, &ncmp, &t_filesize, &t_secsize);
            break;
        default:
            break;
        }
    }

    /* DB close */
    vdbp->close(vdbp, 0);
    fts_close(ftsp);
    free(vdb);
    fclose(fp);

    gettimeofday(&t_etime, NULL);
    sec_elapsed = time_diff(t_etime, t_stime);

    /* report statistics */
    if((fp = fopen("/proc/self/status", "r")) == NULL) {
        bs_errmsg("[!] fopen(): /proc/self/status\n");
        exit(EXIT_FAILURE);
    }
    for(i=0; i<11; i++) {
        if((fgets(buf, 64, fp)) == NULL) {
            bs_errmsg("[!] fgets(): /proc/self/status\n");
            exit(EXIT_FAILURE);
        }
    }
    fclose(fp);

    bs_msg("\n--------------- Querying NN ---------------\n"
           "Processed files  : %u\n"
           "File size        : %.2f MiB\n"
           "Section size     : %.2f MiB (.text or .CODE)\n"
           "# of comparison : %u\n"
           "%s"
           "Time             : %umin %.3fsec\n\n"
           , nfile, 
           (double)t_filesize/(1024*1024), 
           (double)t_secsize/(1024*1024),
           ncmp,
           buf,
           ((unsigned int)sec_elapsed / 60), 
           ((sec_elapsed-(unsigned int)sec_elapsed)+(unsigned int)sec_elapsed%60)
           );
}

int main(int argc, char **argv) 
{
    int c;
    int exe_inst;
    char *db_path = NULL;
    char *input_path = NULL;
    char *out_file = NULL;
    unsigned int vid = 0;
    char *ptr;
    char *file_path = NULL;

    struct option long_options[] = {
        {"help",        no_argument,            0,      'h'},
        {"db",          required_argument,      0,      'd'},
        {"binary",      required_argument,      0,      'b'},
        {"text",        required_argument,      0,      't'},
        {"compare",     no_argument,            0,      'p'},
        {"cluster",     no_argument,            0,      'r'},
        {"neighbor",    required_argument,      0,      'n'},
        {"vinfo",       required_argument,      0,      'q'},
        {"jaccard",     required_argument,      0,      'j'},
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
    while ((c = getopt_long(argc, argv, "hd:b:t:prn:q:j:s:w:zo:", long_options, &option_index)) != -1)
        switch (c) {
            case 'd':
                db_path = strdup(optarg);
                break;
            case 'b':
                input_path = strdup(optarg);
                exe_inst = EXE_ADD_BIN;
                break;
            case 't':
                input_path = strdup(optarg);
                exe_inst = EXE_ADD_TXT;
                break;
            case 'p':
                exe_inst = EXE_COMPARE;
                break;
            case 'r':
                exe_inst = EXE_CLUSTER;
                break;
            case 'n':
                input_path = strdup(optarg);
                exe_inst = EXE_NEIGHBOR;
                break;
            case 'q':
                vid = atoi(optarg);
                exe_inst = EXE_GETVINFO;
                break;
            case 'j':
                threshold = atof(optarg);
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
                    bs_errmsg("[!] %s fopen()\n", out_file);
                    exit(EXIT_FAILURE);
                }
                break;
            case '?':
                if (optopt=='j' || optopt=='s' || optopt=='w')
                    bs_errmsg("[!] missing argument value for -%c option\n", optopt);
                else if (optopt=='d' || optopt=='b' || optopt=='t' || optopt=='o' || optopt=='n')
                    bs_errmsg("[!] missing file name for -%c option\n", optopt);
                else if (optopt=='q')
                    bs_errmsg("[!] missing index number for --get option\n");
                else
                    bs_errmsg("[!] unknown option\n");
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
        case EXE_ADD_BIN:
        case EXE_ADD_TXT:
            if(input_path == NULL){
                bs_errmsg("[!] input path missing\n");
                return -1;
            }
            if(db_path == NULL)
                db_path = strdup(DB_PATH);

            update_database(db_path, input_path, exe_inst);
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

        case EXE_GETVINFO:
            if(db_path == NULL)
                db_path = strdup(DB_PATH);
            if(vid == 0){
                bs_errmsg("[!] index number cannot be zero\n");
                return -1;
            }
            get_vinfo(db_path, vid);
            break;

        case EXE_NEIGHBOR:
            if(input_path == NULL) {
                bs_errmsg("[!] input path missing\n");
                return -1;
            }
            if(db_path == NULL)
                db_path = strdup(DB_PATH);

            neighbor(db_path, input_path);
            break;

        default:
            return -1;
    }

    if(db_path) free(db_path);
    if(input_path) free(input_path);
    if(out_file) fclose(stdout);
    return 0;
}
