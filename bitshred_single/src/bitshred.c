#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <db.h>

#include "bs_common.h"
#include "vdb.h"
#include "jaccard.h"
#include "shred.h"

/* global variables */
unsigned int shredsize  = 0;
unsigned int windowsize = WINDOW_SIZE;
double threshold        = JACCARD_THRESHOLD;

/* display the help message */
void usage(void)
{
    bs_msg("Usage: bitshred [OPTION...]\n");
    bs_msg(" -h, --help    = show this help\n\n");
    bs_msg(" -d, --db      = set database path\n");
    bs_msg(" -b, --binary  = cluster by processing binary files\n");
    bs_msg(" -x, --text    = cluster by processing text files\n");
    bs_msg(" -t, --tval    = set clustering threshold value (default: %0.3f)\n", threshold);
    bs_msg(" -s, --size    = set shred size\n", shredsize);
    bs_msg(" -w, --window  = set window size\n", windowsize);
    bs_msg(" --debug       = show all error messages\n");
    bs_msg(" -o, --output  = set output file\n\n");
}

int main(int argc, char **argv) {
    int c;
    int exe_inst;
    char *db_path = NULL;
    char *input_path = NULL;
    char *out_file = NULL;
    char *ptr;
    char *file_path = NULL;
    unsigned int nvirus = 0;

    struct option long_options[] = {
        {"help",        no_argument,            0,      'h'},
        {"db",          required_argument,      0,      'd'},
        {"binary",      required_argument,      0,      'b'},
        {"text",        required_argument,      0,      'x'},
        {"tval",        required_argument,      0,      't'},
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

    umask(0002); // set file access right
    exe_inst = -1;

    opterr = 0;
    while ((c = getopt_long(argc, argv, "hd:b:x:t:s:w:zo:", long_options, &option_index)) != -1)
        switch (c) {
            case 'd':
                db_path = strdup(optarg);
                break;
            case 'b':
                input_path = strdup(optarg);
                exe_inst = EXE_BIN;
                break;
            case 'x':
                input_path = strdup(optarg);
                exe_inst = EXE_TXT;
                break;
            case 't':
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
                if (optopt=='t' || optopt=='s' || optopt=='w')
                    bs_errmsg("[!] missing argument value for -%c option\n", optopt);
                else if (optopt=='d' || optopt=='b' || optopt=='x' || optopt=='o')
                    bs_errmsg("[!] missing file path for -%c option\n", optopt);
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

    if (input_path == NULL) {
        bs_errmsg("[!] missing input path\n");
        return -1;
    }
    if (db_path == NULL)
        db_path = strdup(DB_PATH);

    if (shredsize == 0) {
        if (exe_inst == EXE_BIN) shredsize = SHRED_BIN;
        else if (exe_inst == EXE_TXT) shredsize = SHRED_TXT;
    }

    nvirus = update_vdb(db_path, input_path, exe_inst);
    if (nvirus > 0) cluster_vdb(db_path, nvirus);

    if(db_path) free(db_path);
    if(input_path) free(input_path);
    if(out_file) fclose(stdout);

    return 0;
}
