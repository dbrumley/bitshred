#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <dirent.h>
#include <getopt.h>

#define FP_SIZE (1024*32)     // in bytes
//#define FP_SIZE (1024*8)     // in bytes
#define DB_PATH "./db"

#define EXE_ROW 0
#define EXE_COL 1
    
unsigned int shredsize = 16;
unsigned int windowsize = 1;
int outer_iter_num;
int inner_iter_num;
int global_rnum;
int global_cnum;

typedef struct {
    char path[128];
} sample_t;

void row_proc(char *db_path) {
    DIR *dirp;
    struct dirent *entry;
    int nfiles;
    int nsamples;
    int fp_per_file;
    FILE *fp;
    char buf[128];
    int n, c, index;
    int *global_r;
    sample_t *sample_list;
    int i, j;

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
        perror("data fopen()");
        exit(EXIT_FAILURE);
    }
    fseek(fp, 0L, SEEK_END);
    fp_per_file = ftell(fp)/FP_SIZE;
    fclose(fp);
    nsamples = nfiles*fp_per_file;

    if((global_r = (int *)malloc(nsamples*sizeof(int)))==NULL) {
        perror("globalr malloc()");
        exit(EXIT_FAILURE);
    }
    snprintf(buf, 128, "%s/global/r_%d_%d_%d_%d.new", db_path, outer_iter_num, inner_iter_num, global_rnum, global_cnum);
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

    if((sample_list = (sample_t *)calloc(sizeof(sample_t), nsamples))==NULL) {
        perror("sample_list calloc()");
        exit(EXIT_FAILURE);
    }
    if((fp = fopen("cclist.log", "r"))==NULL) {
        perror("cclist fopen()");
        exit(EXIT_FAILURE);
    }
    index = 0;
    while(fgets(sample_list[index].path, 128, fp)){
        index++;
    }
    fclose(fp);

    snprintf(buf, 128, "%s/rowgroup.log", db_path);
    if((fp = fopen(buf, "w"))==NULL) {
        perror("rowgroup fopen()");
        exit(EXIT_FAILURE);
    }
    for(i=0; i<global_rnum; i++) {
        fprintf(fp, "[%d row groups]\n", i);
        for(j=0; j<nsamples; j++) {
            if(global_r[j]==i) {
                fprintf(fp, "%s", sample_list[j].path);
            }
        }
        fprintf(fp, "\n");
    }
    fclose(fp);

    free(global_r);
    free(sample_list);
}

typedef struct feature {
    int offset;
    char shred[16];
    uint32_t hash;
    struct feature *next;
} feature_t;

/* Hash functions */
inline unsigned int djb2(unsigned char *str) {
    unsigned int hash = 5381;
    int c;
    size_t i;

    for(i= 0; i< shredsize; i++) {
        c = *str++;
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }

    return hash;
}

int col_proc_helper(char *sample_path, feature_t **feature_list) {
    int i, j, k;
    int nshred = 0;
    uint32_t minhash = 0;
    uint32_t tmphash = 0;
    int minid;
    unsigned int nhash;
    unsigned char *section_data = NULL;
    unsigned char buf[8];
    FILE *fp;
    feature_t *cur;
    feature_t *next;

    if((fp = fopen(sample_path, "r")) == NULL){
        perror("sample fopen()");
        exit(EXIT_FAILURE);
    }

    fseek(fp, 60, SEEK_SET);
    fread(buf, sizeof(char), 4, fp);
    unsigned int offsetOfPEHeader = ((buf[0]&0xFF) | (buf[1]&0xFF)<<8 | (buf[2]&0xFF)<<16 | (buf[3]&0xFF)<<24) & 0xFFFFFFFF;
    fseek(fp, offsetOfPEHeader, SEEK_SET);
    fread(buf, sizeof(char), 8, fp);

    // Check PE file Signature
    if(buf[0]==0x50 && buf[1]==0x45 && buf[2]==0x00 && buf[3]==0x00) {
        unsigned int offsetOfNumberOfSections = offsetOfPEHeader + 6;
        unsigned int offsetOfSizeOfOptHeader = offsetOfPEHeader + 20;
        unsigned int offsetOfEntryPoint = offsetOfPEHeader + 40;
        unsigned int offsetOfImageBase = offsetOfPEHeader + 52;

        fseek(fp, offsetOfNumberOfSections, SEEK_SET);
        fread(buf, sizeof(char), 2, fp);
        unsigned int numberOfSections = (buf[0]&0xFF) | (buf[1]&0xFF)<<8;

        fseek(fp, offsetOfEntryPoint, SEEK_SET);
        fread(buf, sizeof(char), 4, fp);
        unsigned int entryPoint = ((buf[0]&0xFF) | (buf[1]&0xFF)<<8 | (buf[2]&0xFF)<<16 | (buf[3]&0xFF)<<24) & 0xFFFFFFFF;

        fseek(fp, offsetOfImageBase, SEEK_SET);
        fread(buf, sizeof(char), 4, fp);
        unsigned int imageBase = ((buf[0]&0xFF) | (buf[1]&0xFF)<<8 | (buf[2]&0xFF)<<16 | (buf[3]&0xFF)<<24) & 0xFFFFFFFF;

        fseek(fp, offsetOfSizeOfOptHeader, SEEK_SET);
        fread(buf, sizeof(char), 2, fp);
        unsigned int sizeOfOptHeader = (buf[0]&0xFF) | (buf[1]&0xFF)<<8;
        unsigned int offsetOfSectionTable = offsetOfPEHeader + 24 + sizeOfOptHeader;
        /*
        bs_debugmsg("offsetOfPEHeader: %u\n", offsetOfPEHeader);
        bs_debugmsg("offsetOfNumberOfSections: %u\n", offsetOfNumberOfSections);
        bs_debugmsg("offsetOfSizeOfOptHeader: %u\n", offsetOfSizeOfOptHeader);
        bs_debugmsg("offsetOfEntryPoint: %u\n", offsetOfEntryPoint);
        bs_debugmsg("offsetOfImageBase: %u\n", offsetOfImageBase);
        bs_debugmsg("numberOfSections: %u\n", numberOfSections);
        bs_debugmsg("entryPoint: %u\n", entryPoint);
        bs_debugmsg("imageBase: %u\n", imageBase);
        bs_debugmsg("sizeOfOptHeader: %u\n", sizeOfOptHeader);
        bs_debugmsg("offsetOfSectionTable: %u\n", offsetOfSectionTable);
        */
        unsigned int virtualAddress;
        for(k=0; k<numberOfSections; k++) {
            unsigned int offsetOfCurSection = offsetOfSectionTable + (40*k);

            // CODE or .text Section
            /*
            fseek(fp, offsetOfCurSection, SEEK_SET);
            fread(buf, sizeof(char), 8, fp);
            if((buf[0]==0x43 && buf[1]==0x4f && buf[2]==0x44 && buf[3]==0x45) || (buf[0]==0x2e && buf[1]==0x74 && buf[2]==0x65 && buf[3]==0x78 && buf[4]==0x74)) {
                fseek(fp, offsetOfCurSection+8, SEEK_SET);
                fread(buf, sizeof(char), 4, fp);
                unsigned int virtualSize = ((buf[0]&0xFF) | (buf[1]&0xFF)<<8 | (buf[2]&0xFF)<<16 | (buf[3]&0xFF)<<24) & 0xFFFFFFFF;
                fseek(fp, offsetOfCurSection+16, SEEK_SET);
                fread(buf, sizeof(char), 4, fp);
                unsigned int sizeOfRawData = ((buf[0]&0xFF) | (buf[1]&0xFF)<<8 | (buf[2]&0xFF)<<16 | (buf[3]&0xFF)<<24) & 0xFFFFFFFF;
                unsigned int sectionSize = (virtualSize < sizeOfRawData) ? virtualSize : sizeOfRawData;

                if(sectionSize < shredsize) {
                    bs_verbosemsg("Invalid shredsize!\n");
                    fclose(fp);
                    return -1;
                }
                nshred = sectionSize - (shredsize-1);
                if(nshred < windowsize){
                    //fprintf(fp_list, "-:%s:0:0:%s:%s:\n", filepath, virname, packer);
                    bs_verbosemsg("No appropriate sections to be processed!\n");
                    fclose(fp);
                    return -1;
                }

                fseek(fp, offsetOfCurSection+20, SEEK_SET);
                fread(buf, sizeof(char), 4, fp);
                unsigned int pointerToRawData = ((buf[0]&0xFF) | (buf[1]&0xFF)<<8 | (buf[2]&0xFF)<<16 | (buf[3]&0xFF)<<24) & 0xFFFFFFFF;
                section_data = (unsigned char *)malloc(sizeof(char)*sectionSize);
                fseek(fp, pointerToRawData, SEEK_SET);
                fread(section_data, sizeof(char), sectionSize, fp);
            }
            */

            // Executable Section located at Entry Point
            fseek(fp, offsetOfCurSection+12, SEEK_SET);
            fread(buf, sizeof(char), 4, fp);
            virtualAddress = ((buf[0]&0xFF) | (buf[1]&0xFF)<<8 | (buf[2]&0xFF)<<16 | (buf[3]&0xFF)<<24) & 0xFFFFFFFF;
            fseek(fp, offsetOfCurSection+8, SEEK_SET);
            fread(buf, sizeof(char), 4, fp);
            unsigned int virtualSize = ((buf[0]&0xFF) | (buf[1]&0xFF)<<8 | (buf[2]&0xFF)<<16 | (buf[3]&0xFF)<<24) & 0xFFFFFFFF;
            fseek(fp, offsetOfCurSection+16, SEEK_SET);
            fread(buf, sizeof(char), 4, fp);
            unsigned int sizeOfRawData = ((buf[0]&0xFF) | (buf[1]&0xFF)<<8 | (buf[2]&0xFF)<<16 | (buf[3]&0xFF)<<24) & 0xFFFFFFFF;
            unsigned int sectionSize = (virtualSize < sizeOfRawData) ? virtualSize : sizeOfRawData;
            /*
            bs_debugmsg("offsetOfCurSection: %u\n", offsetOfCurSection);
            bs_debugmsg("virtualAddress: %u\n", virtualAddress);
            bs_debugmsg("virtualSize: %u\n", virtualSize);
            bs_debugmsg("sizeOfRawData: %u\n", sizeOfRawData);
            bs_debugmsg("sectionSize: %u\n", sectionSize);
            */
            if((entryPoint >= virtualAddress) && (entryPoint < virtualAddress+sectionSize)) {
                nshred = sectionSize - (shredsize-1);
                if(sectionSize < shredsize || nshred < windowsize){
                    fprintf(stderr, "[!] Invalid section size: %s\n", sample_path);
                    fclose(fp);
                    return -1;
                }

                // IMAGE_SCN_CNT_CODE || IMAGE_SCN_MEM_EXECUTE (Characteristics)
                fseek(fp, offsetOfCurSection+36, SEEK_SET);
                fread(buf, sizeof(char), 4, fp);
                if((buf[0]&0x20)==0x20 || (buf[3]&0x20)==0x20) {
                    fseek(fp, offsetOfCurSection+20, SEEK_SET);
                    fread(buf, sizeof(char), 4, fp);
                    unsigned int pointerToRawData = ((buf[0]&0xFF) | (buf[1]&0xFF)<<8 | (buf[2]&0xFF)<<16 | (buf[3]&0xFF)<<24) & 0xFFFFFFFF;
                    section_data = (unsigned char *)malloc(sizeof(char)*sectionSize);
                    fseek(fp, pointerToRawData, SEEK_SET);
                    if(fread(section_data, sizeof(char), sectionSize, fp)!=sectionSize) {
                        fprintf(stderr, "[!] Corrupted header: %s\n", sample_path);
                        free(section_data);
                        fclose(fp);
                        return -1;
                    }
                }
                break;
            }
        }

        if (section_data != NULL) {
            minid = -1;
            minhash = 0;
            tmphash = 0;
            for(i=0; i<(nshred-windowsize+1); i++) {
                if(minid < i) {
                    minhash = djb2(section_data+i);
                    minid = i;
                    for(j=1; j<windowsize; j++) {
                        tmphash = djb2(section_data+(i+j));
                        if(tmphash <= minhash) {
                            minhash = tmphash;
                            minid = i+j;
                        }
                    }

                    tmphash = minhash & (FP_SIZE*8-1);
                    if((next=(feature_t *)malloc(sizeof(feature_t)))==NULL) {
                        perror("flist malloc()");
                        exit(EXIT_FAILURE);
                    }
                    next->offset = imageBase+virtualAddress+minid;
                    memcpy(next->shred, section_data+minid, shredsize);
                    next->hash = tmphash;
                    next->next = NULL;
                    cur = feature_list[tmphash];
                    if (cur) {
                        while(cur->next) cur=cur->next;
                        cur->next = next;
                    }
                    else {
                        feature_list[tmphash]=next;
                    }
                    //bit_vector_set(sample_bs_fp->bit_vector, minhash & (FP_SIZE*8-1));
                    nhash++;
                }
                else {
                    tmphash = djb2(section_data+(i+windowsize-1));
                    if(tmphash <= minhash) {
                        minhash = tmphash;
                        minid = i+windowsize-1;

                        tmphash = minhash & (FP_SIZE*8-1);
                        if((next=(feature_t *)malloc(sizeof(feature_t)))==NULL) {
                            perror("flist malloc()");
                            exit(EXIT_FAILURE);
                        }
                        next->offset = imageBase+virtualAddress+minid;
                        memcpy(next->shred, section_data+minid, shredsize);
                        next->hash = tmphash;
                        next->next = NULL;
                        cur = feature_list[tmphash];
                        if (cur) {
                            while(cur->next) cur=cur->next;
                            cur->next = next;
                        }
                        else {
                            feature_list[tmphash]=next;
                        }
                        //bit_vector_set(sample_bs_fp->bit_vector, minhash & (FP_SIZE*8-1));
                        nhash++;
                    }
                }
            }
            free(section_data);
        }
    }
    fclose(fp);
    return nshred;
}

void col_proc(char *db_path, char *sample_path) {
    int *global_c;
    int n, c, index;
    FILE *fp;
    char buf[128];
    feature_t **feature_list;
    feature_t *cur;
    feature_t *prev;
    int i, j;

    if((global_c=(int *)malloc((FP_SIZE*8)*sizeof(int)))==NULL) {
        perror("global_c malloc()");
        exit(EXIT_FAILURE);
    }
    snprintf(buf, 128, "%s/global/c_%d_%d_%d_%d.new", db_path, outer_iter_num, inner_iter_num, global_rnum, global_cnum);
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

    if((feature_list=(feature_t **)calloc(sizeof(feature_t *), FP_SIZE*8))==NULL) {
        perror("feature_list calloc()");
        exit(EXIT_FAILURE);
    }
    col_proc_helper(sample_path, feature_list);

    snprintf(buf, 128, "%s/colgroup.log", db_path);
    if((fp = fopen(buf, "w"))==NULL) {
        perror("colgroup fopen()");
        exit(EXIT_FAILURE);
    }
    for(i=0; i<global_cnum; i++) {
        fprintf(fp, "[%d col groups]\n", i);
        for(j=0; j<FP_SIZE*8; j++) {
            if(global_c[j]==i) {
                // TODO
                cur = feature_list[j];
                while (cur) {
                    fprintf(fp, "%08x:", cur->offset);
                    for(index=0; index<shredsize; index++) {
                        fprintf(fp, "%02x", cur->shred[index]&0x000000FF);
                    }
                    fprintf(fp, ":%6u\n", cur->hash);
                    prev = cur;
                    cur = cur->next;
                    free(prev);
                }
            }
        }
        fprintf(fp, "\n");
    }
    fclose(fp);

    free(global_c);
    free(feature_list);
}

int main(int argc, char **argv) {
    int c;
    int exe_inst;
    char *db_path = NULL;
    char *sample_path = NULL;
    char *ptr;
    
    struct option long_options[] = {
        {"row",     no_argument,        0,  'r'},
        {"col",     required_argument,  0,  'c'},
        {"db",      required_argument,  0,  'd'},
        {"global",  required_argument,  0,  'g'},
        {0,0,0,0}
    };
    int option_index = 0;

    if (argc == 1) {
        fprintf(stderr, "%s -r/c -g\n", argv[0]);
        return -1;
    }

    exe_inst = -1;

    opterr = 0;
    while ((c=getopt_long(argc, argv, "rc:d:g:", long_options, &option_index)) != -1)
        switch (c) {
            case 'd':
                db_path = strdup(optarg);
                break;
            case 'r':
                exe_inst = EXE_ROW;
                break;
            case 'c':
                sample_path = strdup(optarg);
                exe_inst = EXE_COL;
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
            default:
                return -1;
        }

    if(optind < argc) {
        return -1;
    }

    switch (exe_inst) {
        case EXE_ROW:
            if(db_path==NULL)
                db_path = strdup(DB_PATH);
            row_proc(db_path);
            break;
        case EXE_COL:
            if(db_path==NULL)
                db_path = strdup(DB_PATH);
            col_proc(db_path, sample_path);
            break;
        default:
            return -1;
    }
}

