#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <omp.h>
#include <math.h>

#include "vdb.h"
#include "jaccard.h"
//#include "shred.h"
//#include "unpack.h"

extern unsigned int limit;
extern double threshold;
extern unsigned int shredsize;
extern unsigned int windowsize;

int update_vdb_helper(sample_t *sample, int vdbid, bitshred_t *vdb, int offset) {
    int i, j, k;
//    char *ptr;
//    char file_md5[33];
//    shred_t *shredp = NULL;
    int nshred = 0;
//    unsigned int filesize = 0;
//    unsigned int secsize = 0;
//    DBT key, data;
    uint32_t minhash = 0;
    uint32_t tmphash = 0;
    int minid;
    unsigned int nhash;
//    FILE *fp;
//    char *filebuf = NULL;
//    size_t fsize;
//    struct exe_info peinfo;
//    int ret_unpack;
//    char file_path[PATH_LEN+1];
    bitshred_t *sample_vdb = NULL;
//    bincode_t *bin;
//    struct section *sec;
//    bfd_vma entry;
    unsigned char *section_data = NULL;
    FILE *fp;
    unsigned char buf[8];


    /* Try to unpack the binary */
//    ret_unpack = unpack(filepath);
//    if (ret_unpack == UNPACK_SUCCESS) {
//        strcat(filepath, ".unpacked");
//    } 
    /* else if (ret_unpack == PACKED_BUT_FAIL) { */
    /* 	return -1; */
    /* } */

    /* */
/*
    if((bin = initialize_bincode(filepath)) != NULL) {
        bs_dbgmsg("[-] using libbfd\n");
        bs_verbosemsg("[%5u/ %5u] %s: ", *nfile+1, limit, filepath);
        nshred = shred_section(bin, &shredp, &filesize, &secsize);
    } else {
        fp = fopen(filepath, "r");
        fseek(fp, 0, SEEK_END);
        fsize = ftell(fp);
        fseek(fp, 0, SEEK_SET);
  
        if ( (filebuf = calloc(fsize,sizeof(char))) == NULL ) {
            perror("filebuf calloc()");
            exit(EXIT_FAILURE);
        }
        
        if(fread(filebuf, sizeof(char), fsize, fp) != fsize) {
            perror("filebuf fread()");
            exit(EXIT_FAILURE);
        }
        fclose(fp);
  
        peinfo.offset = 0;
  
        if (cli_peheader(filebuf,fsize,&peinfo) == 0) {
            bs_dbgmsg("[-] using parsed PE header\n");
            bs_verbosemsg("[%5u/ %5u] %s: ", *nfile+1, limit, filepath);
            filesize = fsize;
            nshred = shred_section_pe(peinfo, filebuf, &shredp, &filesize, &secsize);
        } else {
            perror("Unrecognizd file type");
            return -1;
        }
    }

    if (filebuf == NULL) 
        free (filebuf);
    if (bin != NULL) {
        free_bincode(bin);
    }
*/
//    snprintf(file_path, PATH_LEN, "%s/%s", scratch_path, sample_path);
//    bin = initialize_bincode(sample_path);
//    nshred = shred_section(bin, &shredp, &filesize, &secsize);
//    free_bincode(bin);

//    if(nshred < windowsize){
//        fprintf(fp_list, "-:%s:0:0:%s:%s:\n", filepath, virname, packer);
//        bs_verbosemsg("\tNo appropriate sections to be processed!\n");
//        return -1;
//    }

//    ptr = strrchr(sample_path, '/');
//    strncpy(file_md5, ++ptr, 32);
//    file_md5[32] = '\0';

    if((fp = fopen(sample->sample_path, "r")) == NULL){
        perror("fp fopen()");
        exit(EXIT_FAILURE);
    }
    sample->sample_id = vdbid*FP_PER_FILE + offset;

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
            unsigned int virtualAddress = ((buf[0]&0xFF) | (buf[1]&0xFF)<<8 | (buf[2]&0xFF)<<16 | (buf[3]&0xFF)<<24) & 0xFFFFFFFF;
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
                if(sectionSize < shredsize) {
//                    bs_verbosemsg("[%5u] %s: Invalid sectionsize! (%u)\n", sample_id, sample_path, sectionSize);
                    bs_verbosemsg("[%5u] Invalid sectionsize! (%u)\n", sample->sample_id, sample->sample_path, sectionSize);
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

                // IMAGE_SCN_CNT_CODE || IMAGE_SCN_MEM_EXECUTE (Characteristics)
                fseek(fp, offsetOfCurSection+36, SEEK_SET);
                fread(buf, sizeof(char), 4, fp);
                if((buf[0]&0x20)==0x20 || (buf[3]&0x20)==0x20) {
                    fseek(fp, offsetOfCurSection+20, SEEK_SET);
                    fread(buf, sizeof(char), 4, fp);
                    unsigned int pointerToRawData = ((buf[0]&0xFF) | (buf[1]&0xFF)<<8 | (buf[2]&0xFF)<<16 | (buf[3]&0xFF)<<24) & 0xFFFFFFFF;
                    section_data = (unsigned char *)malloc(sizeof(char)*sectionSize);
                    fseek(fp, pointerToRawData, SEEK_SET);
                    fread(section_data, sizeof(char), sectionSize, fp);
                }
                break;
            }
        }

        if (section_data != NULL) {
            sample_vdb = vdb+offset;
            bs_init(sample_vdb);
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
                    bit_vector_set(sample_vdb->bit_vector, minhash & (FP_SIZE*8-1));
                    nhash++;
                }
                else {
                    tmphash = djb2(section_data+(i+windowsize-1));
                    if(tmphash <= minhash) {
                        minhash = tmphash;
                        minid = i+windowsize-1;
                        bit_vector_set(sample_vdb->bit_vector, minhash & (FP_SIZE*8-1));
                        nhash++;
                    }
                }
            }
            free(section_data);
//            bs_verbosemsg("[%5u] %s: %llu shreds\n", sample_id, sample_path, nshred);
//            bs_verbosemsg("[%5u] %d shreds\n", sample_id, nshred);
        }
    }
    fclose(fp);
    return nshred;
/*
    entry = bfd_get_start_address(bin->abfd);
    sec = bin->sec;
    while(sec) {
        // consider executable section located at entry point 
        if (!sec->is_code || entry < sec->vma || entry >= (sec->vma+sec->datasize)) {
            sec = sec->next;
            continue;
        }
        
        // consider section whose name is .text or CODE 
//        if (strcmp(sec->name, ".text")!=0 && strcmp(sec->name, "CODE")!=0) {
//           sec = sec->next;
//           continue;
//        }
        
        if(sec->datasize < shredsize) {
            bs_verbosemsg("\b\b\b\bInvalid shredsize!\n");
            free_bincode(bin);
            return -1;
        }
        nshred = sec->datasize - (shredsize-1);
        if(nshred < windowsize){
            //fprintf(fp_list, "-:%s:0:0:%s:%s:\n", filepath, virname, packer);
            bs_verbosemsg("\tNo appropriate sections to be processed!\n");
            free_bincode(bin);
            return -1;
        }

        section_data = sec->data;
        sample_vdb = ((bitshred_t *)vdb)+sample_id;
        bs_init(sample_vdb);
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
                bit_vector_set(sample_vdb->bit_vector, minhash & (FP_SIZE*8-1));
                nhash++;
            }
            else {
                tmphash = djb2(section_data+(i+windowsize-1));
                if(tmphash <= minhash) {
                    minhash = tmphash;
                    minid = i+windowsize-1;
                    bit_vector_set(sample_vdb->bit_vector, minhash & (FP_SIZE*8-1));
                    nhash++;
                }
            }
        }
        bs_verbosemsg("[%5u] %s: %llu shreds\n", sample_id, sample_path, nshred);
        break;
        //sec = sec->next;
    }
    free_bincode(bin);
*/
/*
    // Fingerprint creation
    sample_vdb = ((bitshred_t *)vdb)+sample_id;
    bs_init(sample_vdb);
    nhash = 0;
    minid = -1;
    for(i=0; i<(nshred-windowsize+1); i++){
        if(minid < i) {
            minhash = shredp[i].hash;
            minid = i;
            for(j=1;j<windowsize;j++) {
                if(shredp[i+j].hash <= minhash){
                    minhash = shredp[i+j].hash;
                    minid = i+j;
                }
            }
            bit_vector_set(sample_vdb->bit_vector, minhash & (FP_SIZE*8-1));
            nhash++;
        }
        else {
            if(shredp[i+windowsize-1].hash <= minhash) {
                minhash = shredp[i+windowsize-1].hash;
                minid = i+windowsize-1;
                bit_vector_set(sample_vdb->bit_vector, minhash & (FP_SIZE*8-1));
                nhash++;
            }
        }
    }

//    *t_filesize += filesize;
//    *t_secsize += secsize;
    free(shredp);
*/
//    fprintf(fp_list, "%u:%s:%u:%u:%s:%s:\n", nvirus+*nfile+1, filepath, nshred, nhash, virname, packer);
/*    
    // DB insertion
    vdb->nshred = nhash;
    strncpy(vdb->virname, virname, VNAME_LEN);
    vdb->virname[VNAME_LEN] = '\0';
    strncpy(vdb->file_md5, file_md5, 32);
    vdb->file_md5[32] = '\0';
    strncpy(vdb->packer, packer, PACKER_LEN);
    vdb->packer[PACKER_LEN] = '\0';

    memset(&key, 0, sizeof(key));
    memset(&data, 0, sizeof(data));
    data.data = vdb;
    data.size = sizeof(bitshred_t);
    dbp->put(dbp, NULL, &key, &data, DB_APPEND);
    *nfile += 1;
*/
}

int update_vdb(char *scratch_path, sample_t *sample_list, int nsamples) {
    int maxthreads;
    int chunk;
//    int nblock, blocksize;
    int nvdb = 0;
    struct timeval time_a, time_b;
    double sec_elapsed = 0;
    bitshred_t *vdb;
    int tid;

    gettimeofday(&time_a, NULL);
    maxthreads = omp_get_max_threads();
    chunk = nsamples / maxthreads;
    bs_verbosemsg("%d samples are processed by %d threads (chunk: %d)\n", nsamples, maxthreads, chunk);
//    nblock = (int)sqrt(2*maxthreads);
//    blocksize = (nsamples%nblock==0) ? (nsamples/nblock) : (int)(nsamples/nblock)+1;

    if((vdb = (bitshred_t *)malloc(sizeof(bitshred_t)*nsamples)) == NULL){
        perror("vdb malloc()");
        exit(EXIT_FAILURE);
    }
    // first touch
    #pragma omp parallel shared(vdb) private(tid,time_a,time_b,sec_elapsed)
    {
        tid = omp_get_thread_num();
        memset(vdb+(tid*sizeof(bitshred_t)*FP_PER_FILE), 0, sizeof(bitshred_t)*FP_PER_FILE);

        gettimeofday(&time_b, NULL);
        sec_elapsed = time_diff(time_b, time_a);
        bs_verbosemsg("%d: Touching: %umin %.3fsec\n"
               ,tid
               ,((unsigned int)sec_elapsed / 60), 
               ((sec_elapsed-(unsigned int)sec_elapsed)+(unsigned int)sec_elapsed%60)
               );
    }
    #pragma omp parallel shared(sample_list,nsamples,vdb,nvdb,chunk) private(tid,time_a,time_b,sec_elapsed)
    {
        int i = 0;
        int nproc_per_thread = 0;
        int vdbid = 0;
        char buf[64];
        FILE *fp_vdb;
        //bitshred_t *vdb;
        tid = omp_get_thread_num();
//        struct timeval time_a, time_b;
//        double sec_elapsed = 0;

//        if((vdb = (bitshred_t *)malloc(sizeof(bitshred_t)*FP_PER_FILE)) == NULL){
//            perror("vdb malloc()");
//            exit(EXIT_FAILURE);
//        }

        #pragma omp for schedule(static,chunk) nowait
        for(i=0; i<nsamples; i++) {
            if (nproc_per_thread%FP_PER_FILE == 0) {
                #pragma omp critical
                vdbid = nvdb++;
            }
            update_vdb_helper(sample_list+i, vdbid, vdb+(tid*FP_PER_FILE), nproc_per_thread%FP_PER_FILE);
            nproc_per_thread++;
            if (nproc_per_thread%FP_PER_FILE == 0) {
                sprintf(buf, "%s/db/vdb/vdb%05d", scratch_path, vdbid);
                if((fp_vdb = fopen(buf, "w")) == NULL){
                    perror("fp_vdb fopen()");
                    exit(EXIT_FAILURE);
                }
                fwrite(vdb, sizeof(bitshred_t), FP_PER_FILE, fp_vdb);
                fclose(fp_vdb);

                gettimeofday(&time_a, NULL);
                sec_elapsed = time_diff(time_a, time_b);
                bs_verbosemsg("tid %d: vdb%05d (%umin %.3fsec)\n", 
                        omp_get_thread_num(), vdbid,
                        ((unsigned int)sec_elapsed / 60), 
                        ((sec_elapsed-(unsigned int)sec_elapsed)+(unsigned int)sec_elapsed%60)
                        );
            }
//            nfile++;
            //if (nfile == limit) break;
        }

//        free(vdb);
        //bs_verbosemsg("tid %d: %d samples\n", omp_get_thread_num(), nproc_per_thread);
    }
    free(vdb);
    return 0;
    //return blocksize;
}

int compare_vdb(char *scratch_path, int nsamples) {
//    DB *vdbp;
//    DBT key, data;
//    int ret;
//    unsigned int vid_a, vid_b;
//    bitshred_t *vdb_a = NULL;
//    bitshred_t *vdb_b = NULL;
//    double jaccard_ab;
    int i, j;
//    int totalcmp;
//    FILE *fp_jdb;
//    similarity_t **jdb = NULL;

    char buf[64];
//    FILE *fp_vdb = NULL;
    int chunk;
    int maxthreads;
    int ncmp_per_thread;
//    int sizeH, sizeV, splitId;
    int blocksize, nblocks;
    int gridsize, grid_per_block;
    block_t *cmp_blocks;
    int tid;
//    int njdb = 0;
    bitshred_t *vdb;
    uint8_t *bit_vector;

    struct timeval time_a, time_b;
    double sec_elapsed = 0;

    gettimeofday(&time_a, NULL);

    maxthreads = omp_get_max_threads();
    nblocks = (int)sqrt(2*maxthreads);
    blocksize = nsamples/nblocks;
//    blocksize = (nsamples%nblock==0) ? (nsamples/nblock) : (int)(nsamples/nblock)+1;
    
    if((cmp_blocks = (block_t *)malloc(sizeof(block_t)*maxthreads)) == NULL) {
        perror("cmp_blocks malloc()");
        exit(EXIT_FAILURE);
    }
    tid = 0;
    for(i=0; i<nblocks; i++) {
        for(j=i; j<nblocks; j++) {
            if((i==j) && (i%2==1)) continue;
            cmp_blocks[tid].block_idV = i;
            cmp_blocks[tid].block_idH = j;
            tid++;
        }
    }
    gettimeofday(&time_b, NULL);
    sec_elapsed = time_diff(time_b, time_a);
    bs_verbosemsg("Scheduling: %umin %.3fsec\n"
           ,((unsigned int)sec_elapsed / 60), 
           ((sec_elapsed-(unsigned int)sec_elapsed)+(unsigned int)sec_elapsed%60)
           );
/*
    if((jdb = (similarity_t **)malloc(sizeof(similarity_t *)*maxthreads)) == NULL) {
        perror("jdb malloc()");
        exit(EXIT_FAILURE);
    }
    for(i=0; i<maxthreads; i++) {
        if((jdb[i] = (similarity_t *)malloc(sizeof(similarity_t)*blocksize*blocksize)) == NULL) {
            perror("jdb malloc()");
            exit(EXIT_FAILURE);
        }
    }
*/

/*
    if(nsamples%2 == 0) {
        sizeH = nsamples/2;
        sizeV = nsamples-1;
    }
    else {
        sizeH = (nsamples-1)/2;
        sizeV = nsamples;
    }

    if((jdb = (similarity_t **)malloc(sizeof(similarity_t *)*sizeV)) == NULL) {
        perror("jdb malloc()");
        exit(EXIT_FAILURE);
    }
    for(i=0; i<sizeV; i++) {
        if((jdb[i] = (similarity_t *)malloc(sizeof(similarity_t)*sizeH)) == NULL) {
            perror("jdb malloc()");
            exit(EXIT_FAILURE);
        }
    }
    splitId = (nsamples%2==0) ? (nsamples/2) : (nsamples+1)/2;
    for(i=0; i<sizeV; i++) {
        for(j=0; j<sizeH; j++) {
            if(i<splitId) {
                jdb[i][j].sid_a = i;
                jdb[i][j].sid_b = j+splitId;
            }
            else {
                if((j+splitId)>i) {
                    jdb[i][j].sid_a = i;
                    jdb[i][j].sid_b = j+splitId;
                }
                else {
                    jdb[i][j].sid_a = i-(i-splitId+1)*2;
                    jdb[i][j].sid_b = splitId-(j+1);
                }
            }
        }
    }

    gettimeofday(&time_a, NULL);
    sec_elapsed = time_diff(time_a, time_b);
    bs_verbosemsg("Scheduling: %umin %.3fsec\n"
           ,((unsigned int)sec_elapsed / 60), 
           ((sec_elapsed-(unsigned int)sec_elapsed)+(unsigned int)sec_elapsed%60)
           );
*/
    
    /*
    for(i=0; i<sizeV; i++) {
        for(j=0; j<sizeH; j++) {
            fprintf(fp_jdb, "%4d:%4d ", jdb[i][j].sid_a, jdb[i][j].sid_b);
        }
        fprintf(fp_jdb, "\n");
    }
    fclose(fp_jdb);
    return;
    */
    chunk = (((uint64_t)nsamples*(nsamples-1))/2)/maxthreads;
    bs_verbosemsg("%d samples are processed by %d threads (chunk: %d)\n", nsamples, maxthreads, chunk);

    gridsize = CACHE_SIZE/FP_SIZE;
    grid_per_block = blocksize / gridsize;

    if((vdb = (bitshred_t *)malloc(sizeof(bitshred_t)*maxthreads*blocksize*2)) == NULL){
        perror("vdb malloc()");
        exit(EXIT_FAILURE);
    }
    if((bit_vector = (uint8_t *)malloc(FP_SIZE*maxthreads)) == NULL) {
        perror("tmp_vector malloc()");
        exit(EXIT_FAILURE);
    }
    // first touch
    #pragma omp parallel shared(vdb) private(tid,time_a,time_b,sec_elapsed)
    {
        bitshred_t *thread_vdb;
        tid = omp_get_thread_num();
        thread_vdb = vdb+(tid*blocksize*2);
        memset(thread_vdb, 0, sizeof(bitshred_t)*blocksize*2);
        memset(bit_vector+(tid*FP_SIZE), 0, FP_SIZE);

        gettimeofday(&time_a, NULL);
        sec_elapsed = time_diff(time_a, time_b);
        bs_verbosemsg("%d: Touching: %umin %.3fsec\n"
               ,tid
               ,((unsigned int)sec_elapsed / 60), 
               ((sec_elapsed-(unsigned int)sec_elapsed)+(unsigned int)sec_elapsed%60)
               );
    }
/*    
    sprintf(buf, "%s/db/vdb", scratch_path);
    if((fp_vdb = fopen(buf, "r")) == NULL) {
        perror("fp_vdb fopen()");
        exit(EXIT_FAILURE);
    }

    sprintf(buf, "%s/db/jdb", scratch_path);
    if((fp_jdb = fopen(buf, "w")) == NULL) {
        perror("fp_jdb fopen()");
        exit(EXIT_FAILURE);
    }
*/
    sprintf(buf, "%s/db/jdb", scratch_path);
    if(access(buf, F_OK)) 
        mkdir(buf, S_IRWXU|S_IXGRP|S_IRGRP|S_IROTH|S_IXOTH);
    

    #pragma omp parallel shared(vdb,bit_vector,cmp_blocks,blocksize,gridsize) private(tid,i,ncmp_per_thread,time_a,time_b,sec_elapsed,buf) 
    {
        bitshred_t *block_vdbV = NULL;
        bitshred_t *block_vdbH = NULL;
        bitshred_t *grid_vdbV = NULL;
        bitshred_t *grid_vdbH = NULL;
//        similarity_t *jdb = NULL;
        int block_idV, block_idH;
        int grid_idV, grid_idH;
        int file_idV, file_idH;
        int grid_offsetV, grid_offsetH;
        int offsetV, offsetH;
//        int jid;
        uint8_t *tmp_vector;
        FILE *fp_jdb = NULL;
        FILE *fp_vdb = NULL;
        float jaccard_ab;
        int vdbs_per_block;
        int vdbid;
//        int jdbid = 0;

//        if((tmp_vector = (uint8_t *)malloc(FP_SIZE)) == NULL) {
//            perror("tmp_vector malloc()");
//            exit(EXIT_FAILURE);
//        }

        vdbs_per_block = blocksize/FP_PER_FILE;
        tid = omp_get_thread_num();
        block_idV = cmp_blocks[tid].block_idV;
        block_idH = cmp_blocks[tid].block_idH;
        ncmp_per_thread = 0;
        gettimeofday(&time_a, NULL);

        sprintf(buf, "%s/db/jdb/jdb%05d", scratch_path, tid);
        if((fp_jdb = fopen(buf, "w")) == NULL) {
            perror("fp_jdb fopen()");
            exit(EXIT_FAILURE);
        }
        tmp_vector = bit_vector+(tid*FP_SIZE);
/*
        if((jdb = (similarity_t *)malloc(sizeof(similarity_t)*blocksize)) == NULL) {
            perror("jdb malloc()");
            exit(EXIT_FAILURE);
        }

        jid=0;
*/
        if(block_idV == block_idH) {
//            if((block_vdbV = (bitshred_t *)malloc(sizeof(bitshred_t)*blocksize)) == NULL){
//                perror("block_vdbV malloc()");
//                exit(EXIT_FAILURE);
//            }
            block_vdbV = vdb+(tid*blocksize*2);
            while(block_idV < block_idH+2) {
                for (vdbid=0; vdbid<vdbs_per_block; vdbid++) {
                    sprintf(buf, "%s/db/vdb/vdb%05d", scratch_path, (block_idV*vdbs_per_block)+vdbid);
                    if((fp_vdb = fopen(buf, "r")) == NULL) {
                        perror("fp_vdb fopen()");
                        exit(EXIT_FAILURE);
                    }
    //                fseek(fp_vdb, block_idV*blocksize*sizeof(bitshred_t), SEEK_SET);
                    fread(block_vdbV+(FP_PER_FILE*vdbid), FP_PER_FILE, sizeof(bitshred_t), fp_vdb);
                    fclose(fp_vdb);
                }

                gettimeofday(&time_b, NULL);
                sec_elapsed = time_diff(time_b, time_a);
                bs_verbosemsg("%d: Loading_ %d : %umin %.3fsec\n"
                       ,tid
                       ,block_idV
                       ,((unsigned int)sec_elapsed / 60), 
                       ((sec_elapsed-(unsigned int)sec_elapsed)+(unsigned int)sec_elapsed%60)
                       );

                for(grid_idV=0; grid_idV<grid_per_block; grid_idV++) {
                    for(grid_idH=grid_idV; grid_idH<grid_per_block; grid_idH++) {
                        grid_offsetV = gridsize*grid_idV;
                        grid_offsetH = gridsize*grid_idH;
                        offsetV = (blocksize*block_idV)+grid_offsetV;
                        offsetH = (blocksize*block_idH)+grid_offsetH;
                        grid_vdbV = ((bitshred_t *)block_vdbV)+grid_offsetV;
                        grid_vdbH = ((bitshred_t *)block_vdbV)+grid_offsetH;

                        if(grid_idV == grid_idH) {
                            for(file_idV=0; file_idV<gridsize-1; file_idV++) {
                                for(file_idH=file_idV+1; file_idH<gridsize; file_idH++) {
                                    jaccard_ab = jaccard_vdb(grid_vdbV+file_idV, grid_vdbH+file_idH, tmp_vector);
                                    if(jaccard_ab >= 0.5) {
                                        fprintf(fp_jdb, "%d:%d:%0.3f:\n", offsetV+file_idV, offsetH+file_idH, jaccard_ab);
//                                        jdb[jid].sid_a = offsetV+file_idV;
//                                        jdb[jid].sid_b = offsetH+file_idH;
//                                        jdb[jid].sim = jaccard_ab;
//                                        jid++;
//                                        if (jid%blocksize==0) {
//                                            if((jdb = (similarity_t *)realloc(jdb, sizeof(similarity_t)*(jid+blocksize))) == NULL) {
//                                                perror("jdb realloc()");
//                                                exit(EXIT_FAILURE);
//                                            }
//                                        }
                                    }

                                    ncmp_per_thread++;
                                    if(ncmp_per_thread%1000000==0) {
                                        gettimeofday(&time_b, NULL);
                                        sec_elapsed = time_diff(time_b, time_a);
                                        bs_verbosemsg("%d: Comparing %d: %umin %.3fsec\n"
                                               ,tid
                                               ,ncmp_per_thread
                                               ,((unsigned int)sec_elapsed / 60), 
                                               ((sec_elapsed-(unsigned int)sec_elapsed)+(unsigned int)sec_elapsed%60)
                                               );
                                    }
                                }
                            }
                        }
                        else {
                            for(file_idV=0; file_idV<gridsize; file_idV++) {
                                for(file_idH=0; file_idH<gridsize; file_idH++) {
                                    jaccard_ab = jaccard_vdb(grid_vdbV+file_idV, grid_vdbH+file_idH, tmp_vector);
                                    if(jaccard_ab >= 0.5) {
                                        fprintf(fp_jdb, "%d:%d:%0.3f:\n", offsetV+file_idV, offsetH+file_idH, jaccard_ab);
//                                        jdb[jid].sid_a = offsetV+file_idV;
//                                        jdb[jid].sid_b = offsetH+file_idH;
//                                        jdb[jid].sim = jaccard_ab;
//                                        jid++;
//                                        if (jid%blocksize==0) {
//                                            if((jdb = (similarity_t *)realloc(jdb, sizeof(similarity_t)*(jid+blocksize))) == NULL) {
//                                                perror("jdb realloc()");
//                                                exit(EXIT_FAILURE);
//                                            }
//                                        }
                                    }

                                    ncmp_per_thread++;
                                    if(ncmp_per_thread%1000000==0) {
                                        gettimeofday(&time_b, NULL);
                                        sec_elapsed = time_diff(time_b, time_a);
                                        bs_verbosemsg("%d: Comparing %d: %umin %.3fsec\n"
                                               ,tid
                                               ,ncmp_per_thread
                                               ,((unsigned int)sec_elapsed / 60), 
                                               ((sec_elapsed-(unsigned int)sec_elapsed)+(unsigned int)sec_elapsed%60)
                                               );
                                    }
                                }
                            }
                        }
                    }
                }
                block_idV++;
            }
//            jdb[tid][jdb_id].sid_a = -1;
        }
        else {
//            if((block_vdbV = (bitshred_t *)malloc(sizeof(bitshred_t)*blocksize)) == NULL){
//                perror("block_vdbV malloc()");
//                exit(EXIT_FAILURE);
//            }
            block_vdbV = vdb+(tid*blocksize*2);
            for (vdbid=0; vdbid<vdbs_per_block; vdbid++) {
                sprintf(buf, "%s/db/vdb/vdb%05d", scratch_path, (block_idV*vdbs_per_block)+vdbid);
                if((fp_vdb = fopen(buf, "r")) == NULL) {
                    perror("fp_vdb fopen()");
                    exit(EXIT_FAILURE);
                }
//                fseek(fp_vdb, block_idV*blocksize*sizeof(bitshred_t), SEEK_SET);
                fread(block_vdbV+(FP_PER_FILE*vdbid), FP_PER_FILE, sizeof(bitshred_t), fp_vdb);
                fclose(fp_vdb);
            }
//            sprintf(buf, "%s/db/vdb/vdb%05d", scratch_path, block_idV*(blocksize/FP_PER_FILE));
//            if((fp_vdb = fopen(buf, "r")) == NULL) {
//                perror("fp_vdb fopen()");
//                exit(EXIT_FAILURE);
//            }
////            fseek(fp_vdb, block_idV*blocksize*sizeof(bitshred_t), SEEK_SET);
//            fread(block_vdbV, blocksize, sizeof(bitshred_t), fp_vdb);
//            fclose(fp_vdb);

//            if((block_vdbH = (bitshred_t *)malloc(sizeof(bitshred_t)*blocksize)) == NULL){
//                perror("block_vdbH malloc()");
//                exit(EXIT_FAILURE);
//            }
            block_vdbH = vdb+(tid*blocksize*2)+blocksize;
            for (vdbid=0; vdbid<vdbs_per_block; vdbid++) {
                sprintf(buf, "%s/db/vdb/vdb%05d", scratch_path, (block_idH*vdbs_per_block)+vdbid);
                if((fp_vdb = fopen(buf, "r")) == NULL) {
                    perror("fp_vdb fopen()");
                    exit(EXIT_FAILURE);
                }
//                fseek(fp_vdb, block_idV*blocksize*sizeof(bitshred_t), SEEK_SET);
                fread(block_vdbH+(FP_PER_FILE*vdbid), FP_PER_FILE, sizeof(bitshred_t), fp_vdb);
                fclose(fp_vdb);
            }

            gettimeofday(&time_b, NULL);
            sec_elapsed = time_diff(time_b, time_a);
            bs_verbosemsg("%d: Loading %d : %umin %.3fsec\n"
                   ,tid
                   ,block_idV
                   ,((unsigned int)sec_elapsed / 60), 
                   ((sec_elapsed-(unsigned int)sec_elapsed)+(unsigned int)sec_elapsed%60)
                   );

//            sprintf(buf, "%s/db/vdb/vdb%05d", scratch_path, block_idH*(blocksize/FP_PER_FILE));
//            if((fp_vdb = fopen(buf, "r")) == NULL) {
//                perror("fp_vdb fopen()");
//                exit(EXIT_FAILURE);
//            }
////            fseek(fp_vdb, block_idH*blocksize*sizeof(bitshred_t), SEEK_SET);
//            fread(block_vdbH, blocksize, sizeof(bitshred_t), fp_vdb);
//            fclose(fp_vdb);

            for(grid_idV=0; grid_idV<grid_per_block; grid_idV++) {
                for(grid_idH=0; grid_idH<grid_per_block; grid_idH++) {
                    grid_offsetV = gridsize*grid_idV;
                    grid_offsetH = gridsize*grid_idH;
                    offsetV = (blocksize*block_idV)+grid_offsetV;
                    offsetH = (blocksize*block_idH)+grid_offsetH;
                    grid_vdbV = ((bitshred_t *)block_vdbV)+grid_offsetV;
                    grid_vdbH = ((bitshred_t *)block_vdbH)+grid_offsetH;

                    for(file_idV=0; file_idV<gridsize; file_idV++) {
                        for(file_idH=0; file_idH<gridsize; file_idH++) {
                            jaccard_ab = jaccard_vdb(grid_vdbV+file_idV, grid_vdbH+file_idH, tmp_vector);
                            if (jaccard_ab >= 0.5) {
                                fprintf(fp_jdb, "%d:%d:%0.3f:\n", offsetV+file_idV, offsetH+file_idH, jaccard_ab);
//                                jdb[jid].sid_a = offsetV+file_idV;
//                                jdb[jid].sid_b = offsetH+file_idH;
//                                jdb[jid].sim = jaccard_ab;
//                                jid++;
//                                if (jid%blocksize==0) {
//                                    if((jdb = (similarity_t *)realloc(jdb, sizeof(similarity_t)*(jid+blocksize))) == NULL) {
//                                        perror("jdb realloc()");
//                                        exit(EXIT_FAILURE);
//                                    }
//                                }
                            }

                            ncmp_per_thread++;
                            if(ncmp_per_thread%1000000==0) {
                                gettimeofday(&time_b, NULL);
                                sec_elapsed = time_diff(time_b, time_a);
                                bs_verbosemsg("%d: Comparing %d: %umin %.3fsec\n"
                                       ,tid
                                       ,ncmp_per_thread
                                       ,((unsigned int)sec_elapsed / 60), 
                                       ((sec_elapsed-(unsigned int)sec_elapsed)+(unsigned int)sec_elapsed%60)
                                       );
                            }
                        }
                    }
                }
            }
//            free(block_vdbH);
//            jdb[tid][jdb_id].sid_a = -1;
        }
//        free(block_vdbV);
//        free(tmp_vector);
        fclose(fp_jdb);

        gettimeofday(&time_b, NULL);
        sec_elapsed = time_diff(time_b, time_a);
        bs_verbosemsg("%d: Comparing %d: %umin %.3fsec\n"
               ,tid
               ,ncmp_per_thread
               ,((unsigned int)sec_elapsed / 60), 
               ((sec_elapsed-(unsigned int)sec_elapsed)+(unsigned int)sec_elapsed%60)
               );
/*
        #pragma omp atomic
        jdbid = njdb++;

        sprintf(buf, "%s/db/jdb/jdb%05d", scratch_path, jdbid);
        if((fp_jdb = fopen(buf, "w")) == NULL) {
            perror("fp_jdb fopen()");
            exit(EXIT_FAILURE);
        }
        for(i=0; i<jid; i++) {
            fprintf(fp_jdb, "%d:%d:%.3f:\n", jdb[i].sid_a, jdb[i].sid_b, jdb[i].sim);
        }
        free(jdb);
        fclose(fp_jdb);

        gettimeofday(&time_a, NULL);
        sec_elapsed = time_diff(time_a, time_b);
        bs_verbosemsg("%d: Writing to jdb%05d: %umin %.3fsec\n"
               ,tid, jdbid
               ,((unsigned int)sec_elapsed / 60), 
               ((sec_elapsed-(unsigned int)sec_elapsed)+(unsigned int)sec_elapsed%60)
               );
*/
    } 
    free(cmp_blocks);
    free(bit_vector);
    free(vdb);
//    fclose(fp_vdb);
    
    /* 
//    ncmp_per_thread = 0;
    #pragma omp parallel for collapse(2) shared(vdb,jdb,chunk) private(i,j)
        for(i=1; i<nsamples; i++) {
            for(j=0; j<i; j++) {
                jdb[i-1][j].sim = jaccard_vdb(vdb+i, vdb+j);
                *ncmp += 1;
//                ncmp_per_thread++;
            }
        }
//        bs_verbosemsg("tid %d: %d cmps\n", omp_get_thread_num(), ncmp_per_thread);
    bs_verbosemsg("total %d cmps\n",*ncmp);
    free(vdb);
    */
/*
    gettimeofday(&time_a, NULL);

//    bs_verbosemsg("Writing to jdb...\n");
    sprintf(buf, "%s/db/jdb", scratch_path);
    if((fp_jdb = fopen(buf, "w")) == NULL) {
        perror("fp_jdb fopen()");
        exit(EXIT_FAILURE);
    }
    for(i=0; i<maxthreads; i++) {
        j=0;
        while(jdb[i][j].sid_a != -1) {
            fprintf(fp_jdb, "%d:%d:%0.3f:\n", jdb[i][j].sid_a, jdb[i][j].sid_b, jdb[i][j].sim);
            j++;
        }
        free(jdb[i]);

        gettimeofday(&time_b, NULL);
        sec_elapsed = time_diff(time_b, time_a);
        bs_verbosemsg("%d: Writing: %umin %.3fsec\n"
               ,i
               ,((unsigned int)sec_elapsed / 60), 
               ((sec_elapsed-(unsigned int)sec_elapsed)+(unsigned int)sec_elapsed%60)
               );
    }
    free(cmp_blocks);
    free(jdb);
    fclose(fp_jdb);
*/

/*
    if((vdb_a = (bitshred_t *) malloc(sizeof(bitshred_t))) == NULL) {
        perror("vdb_a malloc()");
        exit(EXIT_FAILURE);
    }

    bs_verbosemsg("[-] Comparing samples in database...     ");

    totalcmp = (nvirus*nvirus_added)+((nvirus_added*(nvirus_added-1))/2);

    for(i=0; i<nvirus; i++) {
        vid_a = i+1;
        memset(&key, 0, sizeof(key));
        memset(&data, 0, sizeof(data));
        key.data = &vid_a;
        key.size = 4;
        vdbp->get(vdbp, NULL, &key, &data, 0);
        memcpy(vdb_a, data.data, data.size);
        for(j=0; j<nvirus_added; j++) {
            vid_b = nvirus+j+1;
            memset(&key, 0, sizeof(key));
            memset(&data, 0, sizeof(data));
            key.data = &vid_b;
            key.size = 4;
            vdbp->get(vdbp, NULL, &key, &data, 0);
            vdb_b = (bitshred_t *)data.data;
            jaccard_ab = jaccard_vdb(vdb_a, vdb_b);
            *ncmp += 1;
            fprintf(jdbp, "%u:%u:%0.6f:\n", vid_a, vid_b, jaccard_ab);
            if(*ncmp%100 == 0)
                bs_verbosemsg("\b\b\b\b%3.0f%%", *ncmp/(totalcmp*0.01));
        }
    }
    for(i=0; i<(nvirus_added-1); i++) {
        vid_a = nvirus+i+1;
        memset(&key, 0, sizeof(key));
        memset(&data, 0, sizeof(data));
        key.data = &vid_a;
        key.size = 4;
        vdbp->get(vdbp, NULL, &key, &data, 0);
        memcpy(vdb_a, data.data, data.size);
        for(j=i+1; j<nvirus_added; j++) {
            vid_b = nvirus+j+1;
            memset(&key, 0, sizeof(key));
            memset(&data, 0, sizeof(data));
            key.data = &vid_b;
            key.size = 4;
            vdbp->get(vdbp, NULL, &key, &data, 0);
            vdb_b = (bitshred_t *)data.data;
            jaccard_ab = jaccard_vdb(vdb_a, vdb_b);
            *ncmp += 1;
            fprintf(jdbp, "%u:%u:%0.6f:\n", vid_a, vid_b, jaccard_ab);
            if(*ncmp%100 == 0)
                bs_verbosemsg("\b\b\b\b%3.0f%%", *ncmp/(totalcmp*0.01));
        }
    }
    bs_verbosemsg("\b\b\b\b100%% done.\n");

    vdbp->close(vdbp, 0);
    free(vdb_a);
    fclose(jdbp);
*/
    return 0;
}

int cluster_vdb(char *scratch_path, int nsamples, sample_t *jdb_list, int njdb) {
    FILE *fp_cdb = NULL;
    char buf[64];
    int ncluster = 0;
    int *cluster_list;
    unsigned int vid_a, vid_b;
    double jaccard_ab;
//    unsigned int index_a, index_b;
    unsigned int i, j;
    unsigned int cid = 0;
    unsigned int tmp_cid = 0;
    unsigned int cnt;
    char *ptr;
    int maxthreads;
    int chunk;

    sprintf(buf, "%s/db/cdb_%03u", scratch_path, (unsigned int)(threshold*100));
    if((fp_cdb = fopen(buf, "w")) == NULL) {
        perror("fp_cdb fopen()"); 
        exit(EXIT_FAILURE);
    }

    if((cluster_list = (int *)calloc(nsamples, sizeof(int))) == NULL) {
        perror("cluster_list calloc()");
        exit(EXIT_FAILURE);
    }

    bs_verbosemsg("[-] Clustering with threshold %.3f ...\n", threshold);

    maxthreads = omp_get_max_threads();
    chunk = nsamples / maxthreads;

    cid = 1;
    #pragma omp parallel shared(njdb,jdb_list,cid,threshold,chunk) private(i,j,buf,ptr,vid_a,vid_b,jaccard_ab,tmp_cid) 
    {
        FILE *fp_jdb = NULL;
        int k;

        #pragma omp for schedule(dynamic,chunk)
        for(k=0; k<njdb; k++) {
            if((fp_jdb = fopen(jdb_list[k].sample_path, "r")) == NULL) {
                perror("fp_jdb fopen()");
                exit(EXIT_FAILURE);
            }

            // format of jaccard db file: "vid_a:vid_b:jaccard_ab:"
            while(fgets(buf, 64, fp_jdb) != NULL) {
                ptr = strtok(buf, ":");
                vid_a = atoi(ptr);
                ptr = strtok(NULL, ":");
                vid_b = atoi(ptr);
                ptr = strtok(NULL, ":");
                jaccard_ab = atof(ptr);

                if(jaccard_ab >= threshold) {
                    #pragma omp critical
                    {
                        if(cluster_list[vid_a] == 0 && cluster_list[vid_b] == 0) {
                            cluster_list[vid_a] = cid;
                            cluster_list[vid_b] = cid;
                            cid++;
                        }
                        else if (cluster_list[vid_a] != 0 && cluster_list[vid_b] == 0 ){
                            cluster_list[vid_b] = cluster_list[vid_a];
                        }
                        else if (cluster_list[vid_a] == 0 && cluster_list[vid_b] != 0 ){
                            cluster_list[vid_a] = cluster_list[vid_b];
                        }
                        else {
                            if (cluster_list[vid_a] != cluster_list[vid_b]) {
                                tmp_cid = cluster_list[vid_b];
                                for(i=0; i<nsamples; i++) {
                                    if(cluster_list[i] == tmp_cid)
                                        cluster_list[i] = cluster_list[vid_a];
                                }
                            }
                        }
                    }
                }
            }
            fclose(fp_jdb);
        }
        bs_verbosemsg("tid %d: done\n", omp_get_thread_num());
    }

    for(i=0; i<nsamples; i++) {
        cid = cluster_list[i];
        if(cid == -1) {
            continue;
        }
        else if(cid == 0) {
            cluster_list[i] = -1;
            vid_a = i+1;
            ncluster++;

            fprintf(fp_cdb, "%u:%u:1:\n", ncluster, vid_a); 
        }
        else {
            cnt = 0;
            ncluster++;
            fprintf(fp_cdb, "%u:", ncluster);
            for(j=i; j<nsamples; j++) {
                if(cluster_list[j] == cid) {
                    cluster_list[j] = -1;
                    vid_a = j+1;
                    fprintf(fp_cdb, "%u ", vid_a);
                    cnt++;
                }
            }
            fprintf(fp_cdb, ":%u:\n", cnt);
        }
    }
//    bs_verbosemsg("done.\n");

    free(cluster_list);
//    fclose(fp_jdb);
    fclose(fp_cdb);

    return ncluster;
}

void get_vinfo(const char *vdb_path, unsigned int vid) {
/*
    DB *dbp;
    DBT key, data;
    int ret;
    bitshred_t *vdb;
    unsigned int bfnum_set = 0, bfnum_clear = 0, bcount = 0;
    unsigned int *arr_ptr;

    if((ret = db_create(&dbp, NULL, 0)) != 0){
        bs_errmsg("db_create: %s\n", db_strerror(ret));
        exit(EXIT_FAILURE);
    }
    if((ret = dbp->open(dbp, NULL, vdb_path, NULL, DB_RECNO, DB_RDONLY, 0664)) != 0){
        dbp->err(dbp, ret, "%s", vdb_path);
        exit(EXIT_FAILURE);
    }

    memset(&key, 0, sizeof(key));
    memset(&data, 0, sizeof(data));

    key.data = &vid;
    key.size = 4;

    if(dbp->get(dbp, NULL, &key, &data, 0) != DB_NOTFOUND){
        vdb = (bitshred_t *) data.data;

        for(arr_ptr = (unsigned int*) vdb->bit_vector;
            arr_ptr < ((unsigned int*)(vdb->bit_vector + BF_SIZE/8));
            arr_ptr += 1){
            bcount = bitcount(*arr_ptr);
            bfnum_set += bcount;
            bfnum_clear += (32 - bcount);
        }

        bs_msg("--------------------  VDB INFO  --------------------\n"
               "vid           : %u\n"
               "virname       : %s\n"
               "file_md5      : %s\n"
               "packer        : %s\n"
               "# of shreds   : %u\n"
               "# of BF set   : %-8u (m/n = %.3f)\n"
               "# of BF clear : %u\n"
               , vid, 
               vdb->virname, 
               vdb->file_md5, 
               vdb->packer, 
               vdb->nshred, 
               bfnum_set, 
               (float)BF_SIZE / vdb->nshred, 
               bfnum_clear
               );
    }
    else{
        bs_msg("Not Found!\n");
    }

    dbp->close(dbp, 0);
*/
}

int endtoend_compare_vdb(char *scratch_path, int nsamples, bitshred_t *vdb, int nblock, int blocksize, similarity_t **jdb) {
//    DB *vdbp;
//    DBT key, data;
//    int ret;
//    unsigned int vid_a, vid_b;
//    bitshred_t *vdb_a = NULL;
//    bitshred_t *vdb_b = NULL;
//    double jaccard_ab;
    int i, j;
//    int totalcmp;
//    FILE *fp_jdb;
//    similarity_t **jdb = NULL;

//    char buf[64];
//    FILE *fp_vdb = NULL;
    int chunk;
    int maxthreads;
    int ncmp_per_thread;
//    int sizeH, sizeV, splitId;
//    int blocksize, nblock;
    int gridsize, grid_per_block;
    block_t *cmp_blocks;
    int tid;

    struct timeval time_a, time_b;
    double sec_elapsed = 0;

    gettimeofday(&time_a, NULL);

    maxthreads = omp_get_max_threads();
//    nblock = (int)sqrt(2*maxthreads);
//    blocksize = (nsamples%nblock==0) ? (nsamples/nblock) : (int)(nsamples/nblock)+1;
    
    if((cmp_blocks = (block_t *)malloc(sizeof(block_t)*maxthreads)) == NULL) {
        perror("cmp_blocks malloc()");
        exit(EXIT_FAILURE);
    }
    tid = 0;
    for(i=0; i<nblock; i++) {
        for(j=i; j<nblock; j++) {
            if((i==j) && (i%2==1)) continue;
            cmp_blocks[tid].block_idV = i;
            cmp_blocks[tid].block_idH = j;
            tid++;
        }
    }
    gettimeofday(&time_b, NULL);
    sec_elapsed = time_diff(time_b, time_a);
    bs_verbosemsg("Scheduling: %umin %.3fsec\n"
           ,((unsigned int)sec_elapsed / 60), 
           ((sec_elapsed-(unsigned int)sec_elapsed)+(unsigned int)sec_elapsed%60)
           );

    if((jdb = (similarity_t **)malloc(sizeof(similarity_t *)*maxthreads)) == NULL) {
        perror("jdb malloc()");
        exit(EXIT_FAILURE);
    }
    for(i=0; i<maxthreads; i++) {
        if((jdb[i] = (similarity_t *)malloc(sizeof(similarity_t)*blocksize*blocksize)) == NULL) {
            perror("jdb malloc()");
            exit(EXIT_FAILURE);
        }
    }

    chunk = (((uint64_t)nsamples*(nsamples-1))/2)/maxthreads;
    bs_verbosemsg("%d samples are processed by %d threads (chunk: %d)\n", nsamples, maxthreads, chunk);

    gridsize = CACHE_SIZE/FP_SIZE;
    grid_per_block = blocksize / gridsize;
/*    
    sprintf(buf, "%s/db/jdb", scratch_path);
    if((fp_jdb = fopen(buf, "w")) == NULL) {
        perror("fp_jdb fopen()");
        exit(EXIT_FAILURE);
    }
*/
    #pragma omp parallel shared(cmp_blocks,blocksize,gridsize,jdb) private(tid,i,ncmp_per_thread,time_a,time_b,sec_elapsed) 
    {
        bitshred_t *block_vdbV = NULL;
        bitshred_t *block_vdbH = NULL;
        bitshred_t *grid_vdbV = NULL;
        bitshred_t *grid_vdbH = NULL;
//        similarity_t *jdb = NULL;
        int block_idV, block_idH;
        int grid_idV, grid_idH;
        int file_idV, file_idH;
        int grid_offsetV, grid_offsetH;
        int offsetV, offsetH;
        int jdb_id;
        uint8_t *tmp_vector;
//        FILE *fp_jdb = NULL;
//        FILE *fp_vdb = NULL;
        float jaccard_ab;

        if((tmp_vector = (uint8_t *)malloc(FP_SIZE)) == NULL) {
            perror("tmp_vector malloc()");
            exit(EXIT_FAILURE);
        }

        tid = omp_get_thread_num();
        block_idV = cmp_blocks[tid].block_idV;
        block_idH = cmp_blocks[tid].block_idH;
        ncmp_per_thread = 0;
        gettimeofday(&time_a, NULL);
/*
        if((jdb = (similarity_t *)malloc(sizeof(similarity_t)*blocksize*blocksize)) == NULL) {
            perror("jdb malloc()");
            exit(EXIT_FAILURE);
        }
*/
        jdb_id=0;
        if(block_idV == block_idH) {
            if((block_vdbV = (bitshred_t *)malloc(sizeof(bitshred_t)*blocksize)) == NULL){
                perror("block_vdbV malloc()");
                exit(EXIT_FAILURE);
            }
            while(block_idV < block_idH+2) {
            /*
                sprintf(buf, "%s/db/vdb/vdb%05d", scratch_path, block_idV);
                if((fp_vdb = fopen(buf, "r")) == NULL) {
                    perror("fp_vdb fopen()");
                    exit(EXIT_FAILURE);
                }
//                fseek(fp_vdb, block_idV*blocksize*sizeof(bitshred_t), SEEK_SET);
                fread(block_vdbV, blocksize, sizeof(bitshred_t), fp_vdb);
                fclose(fp_vdb);
            */
                memcpy(block_vdbV, vdb+(block_idV*blocksize), sizeof(bitshred_t)*blocksize);

                gettimeofday(&time_b, NULL);
                sec_elapsed = time_diff(time_b, time_a);
                bs_verbosemsg("%d: Loading_ %d : %umin %.3fsec\n"
                       ,tid
                       ,block_idV
                       ,((unsigned int)sec_elapsed / 60), 
                       ((sec_elapsed-(unsigned int)sec_elapsed)+(unsigned int)sec_elapsed%60)
                       );

                for(grid_idV=0; grid_idV<grid_per_block; grid_idV++) {
                    for(grid_idH=grid_idV; grid_idH<grid_per_block; grid_idH++) {
                        grid_offsetV = gridsize*grid_idV;
                        grid_offsetH = gridsize*grid_idH;
                        offsetV = (blocksize*block_idV)+grid_offsetV;
                        offsetH = (blocksize*block_idH)+grid_offsetH;
                        grid_vdbV = ((bitshred_t *)block_vdbV)+grid_offsetV;
                        grid_vdbH = ((bitshred_t *)block_vdbV)+grid_offsetH;

                        if(grid_idV == grid_idH) {
                            for(file_idV=0; file_idV<gridsize-1; file_idV++) {
                                for(file_idH=file_idV+1; file_idH<gridsize; file_idH++) {
                                    jaccard_ab = jaccard_vdb(grid_vdbV+file_idV, grid_vdbH+file_idH, tmp_vector);
                                    if(jaccard_ab >= threshold) {
                                        jdb[tid][jdb_id].sid_a = offsetV+file_idV;
                                        jdb[tid][jdb_id].sid_b = offsetH+file_idH;
                                        jdb[tid][jdb_id].sim = jaccard_ab;
                                        jdb_id++;
                                    }

                                    ncmp_per_thread++;
                                    if(ncmp_per_thread%10000000==0) {
                                        gettimeofday(&time_b, NULL);
                                        sec_elapsed = time_diff(time_b, time_a);
                                        bs_verbosemsg("%d: Comparing %d: %umin %.3fsec\n"
                                               ,tid
                                               ,ncmp_per_thread
                                               ,((unsigned int)sec_elapsed / 60), 
                                               ((sec_elapsed-(unsigned int)sec_elapsed)+(unsigned int)sec_elapsed%60)
                                               );
                                    }
                                }
                            }
                        }
                        else {
                            for(file_idV=0; file_idV<gridsize; file_idV++) {
                                for(file_idH=0; file_idH<gridsize; file_idH++) {
                                    jaccard_ab = jaccard_vdb(grid_vdbV+file_idV, grid_vdbH+file_idH, tmp_vector);
                                    if(jaccard_ab >= threshold) {
                                        jdb[tid][jdb_id].sid_a = offsetV+file_idV;
                                        jdb[tid][jdb_id].sid_b = offsetH+file_idH;
                                        jdb[tid][jdb_id].sim = jaccard_ab;
                                        jdb_id++;
                                    }

                                    ncmp_per_thread++;
                                    if(ncmp_per_thread%10000000==0) {
                                        gettimeofday(&time_b, NULL);
                                        sec_elapsed = time_diff(time_b, time_a);
                                        bs_verbosemsg("%d: Comparing %d: %umin %.3fsec\n"
                                               ,tid
                                               ,ncmp_per_thread
                                               ,((unsigned int)sec_elapsed / 60), 
                                               ((sec_elapsed-(unsigned int)sec_elapsed)+(unsigned int)sec_elapsed%60)
                                               );
                                    }
                                }
                            }
                        }
                    }
                }
                block_idV++;
            }
            jdb[tid][jdb_id].sid_a = -1;
        }
        else {
            if((block_vdbV = (bitshred_t *)malloc(sizeof(bitshred_t)*blocksize)) == NULL){
                perror("block_vdbV malloc()");
                exit(EXIT_FAILURE);
            }
            /*
            sprintf(buf, "%s/db/vdb/vdb%05d", scratch_path, block_idV);
            if((fp_vdb = fopen(buf, "r")) == NULL) {
                perror("fp_vdb fopen()");
                exit(EXIT_FAILURE);
            }
//            fseek(fp_vdb, block_idV*blocksize*sizeof(bitshred_t), SEEK_SET);
            fread(block_vdbV, blocksize, sizeof(bitshred_t), fp_vdb);
            fclose(fp_vdb);
            */
            memcpy(block_vdbV, vdb+(block_idV*blocksize), sizeof(bitshred_t)*blocksize);

            gettimeofday(&time_b, NULL);
            sec_elapsed = time_diff(time_b, time_a);
            bs_verbosemsg("%d: Loading %d : %umin %.3fsec\n"
                   ,tid
                   ,block_idV
                   ,((unsigned int)sec_elapsed / 60), 
                   ((sec_elapsed-(unsigned int)sec_elapsed)+(unsigned int)sec_elapsed%60)
                   );

            if((block_vdbH = (bitshred_t *)malloc(sizeof(bitshred_t)*blocksize)) == NULL){
                perror("block_vdbH malloc()");
                exit(EXIT_FAILURE);
            }
            /*
            sprintf(buf, "%s/db/vdb/vdb%05d", scratch_path, block_idH);
            if((fp_vdb = fopen(buf, "r")) == NULL) {
                perror("fp_vdb fopen()");
                exit(EXIT_FAILURE);
            }
//            fseek(fp_vdb, block_idH*blocksize*sizeof(bitshred_t), SEEK_SET);
            fread(block_vdbH, blocksize, sizeof(bitshred_t), fp_vdb);
            fclose(fp_vdb);
            */
            memcpy(block_vdbH, vdb+(block_idH*blocksize), sizeof(bitshred_t)*blocksize);

            for(grid_idV=0; grid_idV<grid_per_block; grid_idV++) {
                for(grid_idH=0; grid_idH<grid_per_block; grid_idH++) {
                    grid_offsetV = gridsize*grid_idV;
                    grid_offsetH = gridsize*grid_idH;
                    offsetV = (blocksize*block_idV)+grid_offsetV;
                    offsetH = (blocksize*block_idH)+grid_offsetH;
                    grid_vdbV = ((bitshred_t *)block_vdbV)+grid_offsetV;
                    grid_vdbH = ((bitshred_t *)block_vdbH)+grid_offsetH;

                    for(file_idV=0; file_idV<gridsize; file_idV++) {
                        for(file_idH=0; file_idH<gridsize; file_idH++) {
                            jaccard_ab = jaccard_vdb(grid_vdbV+file_idV, grid_vdbH+file_idH, tmp_vector);
                            if (jaccard_ab >= threshold) {
                                jdb[tid][jdb_id].sid_a = offsetV+file_idV;
                                jdb[tid][jdb_id].sid_b = offsetH+file_idH;
                                jdb[tid][jdb_id].sim = jaccard_ab;
                                jdb_id++;
                            }

                            ncmp_per_thread++;
                            if(ncmp_per_thread%10000000==0) {
                                gettimeofday(&time_b, NULL);
                                sec_elapsed = time_diff(time_b, time_a);
                                bs_verbosemsg("%d: Comparing %d: %umin %.3fsec\n"
                                       ,tid
                                       ,ncmp_per_thread
                                       ,((unsigned int)sec_elapsed / 60), 
                                       ((sec_elapsed-(unsigned int)sec_elapsed)+(unsigned int)sec_elapsed%60)
                                       );
                            }
                        }
                    }
                }
            }
            free(block_vdbH);
            jdb[tid][jdb_id].sid_a = -1;
        }
        free(block_vdbV);
        free(tmp_vector);

        gettimeofday(&time_b, NULL);
        sec_elapsed = time_diff(time_b, time_a);
        bs_verbosemsg("%d: Comparing %d: %umin %.3fsec\n"
               ,tid
               ,ncmp_per_thread
               ,((unsigned int)sec_elapsed / 60), 
               ((sec_elapsed-(unsigned int)sec_elapsed)+(unsigned int)sec_elapsed%60)
               );
/*
        sprintf(buf, "%s/db/jdb/jdb%05d", scratch_path, tid);
        if((fp_jdb = fopen(buf, "w")) == NULL) {
            perror("fp_jdb fopen()");
            exit(EXIT_FAILURE);
        }
        
        for(i=0; i<jdb_id; i++) {
            fprintf(fp_jdb, "%d:%d:%.6f:\n", jdb[i].sid_a, jdb[i].sid_b, jdb[i].sim);
        }
        free(jdb);
        fclose(fp_jdb);

        gettimeofday(&time_a, NULL);
        sec_elapsed = time_diff(time_a, time_b);
        bs_verbosemsg("%d: Writing: %umin %.3fsec\n"
               ,tid
               ,((unsigned int)sec_elapsed / 60), 
               ((sec_elapsed-(unsigned int)sec_elapsed)+(unsigned int)sec_elapsed%60)
               );
*/
    } 
//    fclose(fp_vdb);
    
    /* 
//    ncmp_per_thread = 0;
    #pragma omp parallel for collapse(2) shared(vdb,jdb,chunk) private(i,j)
        for(i=1; i<nsamples; i++) {
            for(j=0; j<i; j++) {
                jdb[i-1][j].sim = jaccard_vdb(vdb+i, vdb+j);
                *ncmp += 1;
//                ncmp_per_thread++;
            }
        }
//        bs_verbosemsg("tid %d: %d cmps\n", omp_get_thread_num(), ncmp_per_thread);
    bs_verbosemsg("total %d cmps\n",*ncmp);
    free(vdb);
    */
/*
    gettimeofday(&time_a, NULL);

//    bs_verbosemsg("Writing to jdb...\n");
    sprintf(buf, "%s/db/jdb", scratch_path);
    if((fp_jdb = fopen(buf, "w")) == NULL) {
        perror("fp_jdb fopen()");
        exit(EXIT_FAILURE);
    }
    for(i=0; i<maxthreads; i++) {
        j=0;
        while(jdb[i][j].sid_a != -1) {
            fprintf(fp_jdb, "%d:%d:%0.3f:\n", jdb[i][j].sid_a, jdb[i][j].sid_b, jdb[i][j].sim);
            j++;
        }
        free(jdb[i]);

        gettimeofday(&time_b, NULL);
        sec_elapsed = time_diff(time_b, time_a);
        bs_verbosemsg("%d: Writing: %umin %.3fsec\n"
               ,i
               ,((unsigned int)sec_elapsed / 60), 
               ((sec_elapsed-(unsigned int)sec_elapsed)+(unsigned int)sec_elapsed%60)
               );
    }
    */
    free(cmp_blocks);
    free(vdb);
//    free(jdb);
//    fclose(fp_jdb);


/*
    if((vdb_a = (bitshred_t *) malloc(sizeof(bitshred_t))) == NULL) {
        perror("vdb_a malloc()");
        exit(EXIT_FAILURE);
    }

    bs_verbosemsg("[-] Comparing samples in database...     ");

    totalcmp = (nvirus*nvirus_added)+((nvirus_added*(nvirus_added-1))/2);

    for(i=0; i<nvirus; i++) {
        vid_a = i+1;
        memset(&key, 0, sizeof(key));
        memset(&data, 0, sizeof(data));
        key.data = &vid_a;
        key.size = 4;
        vdbp->get(vdbp, NULL, &key, &data, 0);
        memcpy(vdb_a, data.data, data.size);
        for(j=0; j<nvirus_added; j++) {
            vid_b = nvirus+j+1;
            memset(&key, 0, sizeof(key));
            memset(&data, 0, sizeof(data));
            key.data = &vid_b;
            key.size = 4;
            vdbp->get(vdbp, NULL, &key, &data, 0);
            vdb_b = (bitshred_t *)data.data;
            jaccard_ab = jaccard_vdb(vdb_a, vdb_b);
            *ncmp += 1;
            fprintf(jdbp, "%u:%u:%0.6f:\n", vid_a, vid_b, jaccard_ab);
            if(*ncmp%100 == 0)
                bs_verbosemsg("\b\b\b\b%3.0f%%", *ncmp/(totalcmp*0.01));
        }
    }
    for(i=0; i<(nvirus_added-1); i++) {
        vid_a = nvirus+i+1;
        memset(&key, 0, sizeof(key));
        memset(&data, 0, sizeof(data));
        key.data = &vid_a;
        key.size = 4;
        vdbp->get(vdbp, NULL, &key, &data, 0);
        memcpy(vdb_a, data.data, data.size);
        for(j=i+1; j<nvirus_added; j++) {
            vid_b = nvirus+j+1;
            memset(&key, 0, sizeof(key));
            memset(&data, 0, sizeof(data));
            key.data = &vid_b;
            key.size = 4;
            vdbp->get(vdbp, NULL, &key, &data, 0);
            vdb_b = (bitshred_t *)data.data;
            jaccard_ab = jaccard_vdb(vdb_a, vdb_b);
            *ncmp += 1;
            fprintf(jdbp, "%u:%u:%0.6f:\n", vid_a, vid_b, jaccard_ab);
            if(*ncmp%100 == 0)
                bs_verbosemsg("\b\b\b\b%3.0f%%", *ncmp/(totalcmp*0.01));
        }
    }
    bs_verbosemsg("\b\b\b\b100%% done.\n");

    vdbp->close(vdbp, 0);
    free(vdb_a);
    fclose(jdbp);
*/
    return 0;
}

int endtoend_cluster_vdb(char *scratch_path, int nsamples, similarity_t **jdb) {
//    FILE *fp_jdb;
    FILE *fp_cdb;
    char buf[64];
    unsigned int ncluster = 0;
    int *cluster_list;
    unsigned int vid_a, vid_b;
    double jaccard_ab;
//    unsigned int index_a, index_b;
    unsigned int i, j;
    unsigned int cid = 0;
    unsigned int tmp_cid = 0;
    unsigned int cnt;
//    char *ptr;
    int maxthreads;
    int tid;

    sprintf(buf, "%s/db/cdb_%03u", scratch_path, (unsigned int)(threshold*100));
    if((fp_cdb = fopen(buf, "w")) == NULL) {
        perror("fp_cdb fopen()"); 
        exit(EXIT_FAILURE);
    }

    if((cluster_list = (int *)calloc(nsamples, sizeof(int))) == NULL) {
        perror("cluster_list calloc()");
        exit(EXIT_FAILURE);
    }

    bs_verbosemsg("[-] Clustering with threshold %.3f ...\n", threshold);

    maxthreads = omp_get_max_threads();

    // format of jaccard db file: "vid_a:vid_b:jaccard_ab:"
    cid = 1;
    for(tid=0; tid<maxthreads; tid++) {
        bs_verbosemsg("Processing %d jdb...\n", tid);
        j=0;
        while(jdb[tid][j].sid_a != -1) {
            vid_a = jdb[tid][j].sid_a;
            vid_b = jdb[tid][j].sid_b;
            jaccard_ab = jdb[tid][j].sim;

            if(cluster_list[vid_a] == 0 && cluster_list[vid_b] == 0) {
                cluster_list[vid_a] = cid;
                cluster_list[vid_b] = cid;
                cid++;
            }
            else if (cluster_list[vid_a] != 0 && cluster_list[vid_b] == 0 ){
                cluster_list[vid_b] = cluster_list[vid_a];
            }
            else if (cluster_list[vid_a] == 0 && cluster_list[vid_b] != 0 ){
                cluster_list[vid_a] = cluster_list[vid_b];
            }
            else {
                if (cluster_list[vid_a] != cluster_list[vid_b]) {
                    tmp_cid = cluster_list[vid_b];
                    for(i=0; i<nsamples; i++) {
                        if(cluster_list[i] == tmp_cid)
                            cluster_list[i] = cluster_list[vid_a];
                    }
                }
            }
            j++;
        }
    }
    for(i=0; i<maxthreads; i++) 
        free(jdb[i]);
    free(jdb);


    for(i=0; i<nsamples; i++) {
        cid = cluster_list[i];
        if(cid == -1) {
            continue;
        }
        else if(cid == 0) {
            cluster_list[i] = -1;
            vid_a = i+1;
            ncluster++;

            fprintf(fp_cdb, "%u:%u:1:\n", ncluster, vid_a); 
        }
        else {
            cnt = 0;
            ncluster++;
            fprintf(fp_cdb, "%u:", ncluster);
            for(j=i; j<nsamples; j++) {
                if(cluster_list[j] == cid) {
                    cluster_list[j] = -1;
                    vid_a = j+1;
                    fprintf(fp_cdb, "%u ", vid_a);
                    cnt++;
                }
            }
            fprintf(fp_cdb, ":%u:\n", cnt);
        }
    }


    free(cluster_list);
//    fclose(fp_jdb);
    fclose(fp_cdb);

    return ncluster;
}
