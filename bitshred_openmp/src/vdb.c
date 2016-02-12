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

extern unsigned int limit;
extern double threshold;
extern unsigned int shredsize;
extern unsigned int windowsize;

int update_vdb_helper(sample_t *sample, int vdbid, bitshred_t *vdb, int *vdb_nbits, int offset) {
    int i, j, k;
    int nshred = 0;
    uint32_t minhash = 0;
    uint32_t tmphash = 0;
    int minid;
    unsigned int nhash;
    bitshred_t *sample_vdb = NULL;
    int *sample_nbits = NULL;
    int nbits;
    unsigned char *section_data = NULL;
    unsigned char buf[8];
    FILE *fp;

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
                    bs_verbosemsg("[%5u] Invalid sectionsize! (%u)\n", sample->sample_id, sample->sample_path, sectionSize);
                    fclose(fp);
                    return -1;
                }
                nshred = sectionSize - (shredsize-1);
                if(nshred < windowsize){
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
            sample_nbits = vdb_nbits+offset;
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

            // count set bits in a fingerprint
            nbits = 0;
            for(i=0; i<FP_SIZE/4; i++) {
                nbits += bitcount(((unsigned int*)sample_vdb->bit_vector)[i]);
            }
            *sample_nbits = nbits;
        }
    }
    fclose(fp);
    return nshred;
}

int update_vdb(char *db_path, sample_t *sample_list, int nsamples) {
    int maxthreads;
    int chunk;
    int nvdb = 0;
    struct timeval time_a, time_b;
    double sec_elapsed = 0;
    bitshred_t *vdb;
    int *vdb_nbits;
    int tid;

    gettimeofday(&time_a, NULL);

    maxthreads = MAX_THREADS;
    omp_set_num_threads(maxthreads);
    chunk = nsamples/maxthreads;
    bs_verbosemsg("samples: %d/ maxthreads: %d/ chunk: %d\n", nsamples, maxthreads, chunk);

    if((vdb = (bitshred_t *)malloc(sizeof(bitshred_t)*nsamples)) == NULL){
        perror("vdb malloc()");
        exit(EXIT_FAILURE);
    }
    if((vdb_nbits = (int *)malloc(sizeof(int)*nsamples)) == NULL) {
        perror("vdb_nbits malloc()");
        exit(EXIT_FAILURE);
    }

    /* first touch */
    #pragma omp parallel default(shared) private(tid)
    {
        tid = omp_get_thread_num();
        memset(vdb+(tid*FP_PER_FILE), 0, sizeof(bitshred_t)*FP_PER_FILE);
        memset(vdb_nbits+(tid*FP_PER_FILE), 0, sizeof(int)*FP_PER_FILE);
    }

    #pragma omp parallel default(shared) private(tid,time_b,sec_elapsed)
    {
        int i = 0;
        int j = 0;
        int nproc_per_thread = 0;
        int vdbid = 0;
        char buf[64];
        FILE *fp_vdb;
        tid = omp_get_thread_num();
        bitshred_t *thread_vdb;
        int *thread_nbits;

        thread_vdb = vdb+(tid*FP_PER_FILE);
        thread_nbits = vdb_nbits+(tid*FP_PER_FILE);

        #pragma omp for schedule(static,chunk) nowait
        for(i=0; i<nsamples; i++) {
            if (nproc_per_thread%FP_PER_FILE == 0) {
                #pragma omp critical
                vdbid = nvdb++;
            }
            update_vdb_helper(sample_list+i, vdbid, thread_vdb, thread_nbits, nproc_per_thread%FP_PER_FILE);
            nproc_per_thread++;
            if (nproc_per_thread%FP_PER_FILE == 0) {
                sprintf(buf, "%s/vdb/vdb%05d", db_path, vdbid);
                if((fp_vdb = fopen(buf, "w")) == NULL){
                    perror("vdb fopen()");
                    exit(EXIT_FAILURE);
                }
                fwrite(thread_vdb, sizeof(bitshred_t), FP_PER_FILE, fp_vdb);
                fclose(fp_vdb);

                sprintf(buf, "%s/vdb/vdb_nbits%05d", db_path, vdbid);
                if((fp_vdb = fopen(buf, "w")) == NULL){
                    perror("vdb_nbits fopen()");
                    exit(EXIT_FAILURE);
                }
                for(j=0; j<FP_PER_FILE; j++) {
                    fprintf(fp_vdb, "%d\n", *(thread_nbits+j));
                }
                fclose(fp_vdb);

                gettimeofday(&time_b, NULL);
                sec_elapsed = time_diff(time_b, time_a);
                bs_verbosemsg("tid %d: vdb%05d (%umin %.3fsec)\n", 
                        tid, vdbid,
                        ((unsigned int)sec_elapsed / 60), 
                        ((sec_elapsed-(unsigned int)sec_elapsed)+(unsigned int)sec_elapsed%60)
                        );
            }
        }
    }
    free(vdb);
    free(vdb_nbits);
    return 0;
}

int compare_vdb(char *db_path, int nsamples) {
    int i, j;
    char buf[64];
    int maxthreads;
    int ncmp_per_thread;
    int blocksize, nblocks;
    int gridsize, grid_per_block;
    int tid;
    int njdb = 0;
    block_t *cmp_blocks;
    bitshred_t *vdb;
    int *vdb_nbits;
    struct timeval time_a, time_b;
    double sec_elapsed = 0;

    gettimeofday(&time_a, NULL);

    maxthreads = MAX_THREADS;
    omp_set_num_threads(maxthreads);
    nblocks = (int)sqrt(2*maxthreads);
    blocksize = nsamples/nblocks;
    //blocksize = (nsamples%nblock==0) ? (nsamples/nblock) : (int)(nsamples/nblock)+1;
    gridsize = CACHE_SIZE/FP_SIZE;
    grid_per_block = blocksize/gridsize;
    bs_verbosemsg("samples: %d/ maxthreads: %d/ blocksize: %d/ gridsize: %d\n", nsamples, maxthreads, blocksize, gridsize);
    
    if((cmp_blocks = (block_t *)malloc(sizeof(block_t)*maxthreads)) == NULL) {
        perror("cmp_blocks malloc()");
        exit(EXIT_FAILURE);
    }
    if((vdb = (bitshred_t *)malloc(sizeof(bitshred_t)*blocksize*2*maxthreads)) == NULL){
        perror("vdb malloc()");
        exit(EXIT_FAILURE);
    }
    if((vdb_nbits = (int *)malloc(sizeof(int)*blocksize*2*maxthreads)) == NULL){
        perror("vdb_nbits malloc()");
        exit(EXIT_FAILURE);
    }

    /* scheduling jobs */
    tid = 0;
    for(i=0; i<nblocks; i++) {
        for(j=i; j<nblocks; j++) {
            if((i==j) && (i%2==1)) continue;
            cmp_blocks[tid].block_idV = i;
            cmp_blocks[tid].block_idH = j;
            tid++;
        }
    }

    /* first touch */
    #pragma omp parallel default(shared) private(tid)
    {
        tid = omp_get_thread_num();
        bitshred_t *thread_vdb = vdb+(tid*blocksize*2);
        memset(thread_vdb, 0, sizeof(bitshred_t)*blocksize*2);
        int *thread_nbits = vdb_nbits+(tid*blocksize*2);
        memset(thread_nbits, 0, sizeof(int)*blocksize*2);
    }

    sprintf(buf, "%s/jdb", db_path);
    if(access(buf, F_OK)) 
        mkdir(buf, S_IRWXU|S_IXGRP|S_IRGRP|S_IROTH|S_IXOTH);
    
    #pragma omp parallel default(shared) private(tid,i,ncmp_per_thread,time_a,time_b,sec_elapsed,buf) 
    {
        bitshred_t *block_vdbV = NULL;
        bitshred_t *block_vdbH = NULL;
        bitshred_t *grid_vdbV = NULL;
        bitshred_t *grid_vdbH = NULL;
        int *block_nbitsV = NULL;
        int *block_nbitsH = NULL;
        int *grid_nbitsV = NULL;
        int *grid_nbitsH = NULL;
        int *cur_nbits = NULL;
        similarity_t *jdb = NULL;
        int block_idV, block_idH;
        int grid_idV, grid_idH;
        int file_idV, file_idH;
        int grid_offsetV, grid_offsetH;
        int offsetV, offsetH;
        int jid;
        FILE *fp_jdb = NULL;
        FILE *fp_vdb = NULL;
        float jaccard_ab;
        int vdbs_per_block;
        int vdbid;
        int jdbid;

        vdbs_per_block = blocksize/FP_PER_FILE;
        tid = omp_get_thread_num();
        block_idV = cmp_blocks[tid].block_idV;
        block_idH = cmp_blocks[tid].block_idH;
        ncmp_per_thread = 0;

        if((jdb = (similarity_t *)calloc(blocksize*blocksize, sizeof(similarity_t))) == NULL) {
            perror("jdb calloc()");
            exit(EXIT_FAILURE);
        }

        gettimeofday(&time_a, NULL);

        jid=0;
        if(block_idV == block_idH) {
            block_vdbV = vdb+(tid*blocksize*2);
            block_nbitsV = vdb_nbits+(tid*blocksize*2);
            while(block_idV < block_idH+2) {
                for (vdbid=0; vdbid<vdbs_per_block; vdbid++) {
                    sprintf(buf, "%s/vdb/vdb%05d", db_path, (block_idV*vdbs_per_block)+vdbid);
                    if((fp_vdb = fopen(buf, "r")) == NULL) {
                        perror("vdb fopen()");
                        exit(EXIT_FAILURE);
                    }
                    fread(block_vdbV+(FP_PER_FILE*vdbid), FP_PER_FILE, sizeof(bitshred_t), fp_vdb);
                    fclose(fp_vdb);

                    sprintf(buf, "%s/vdb/vdb_nbits%05d", db_path, (block_idV*vdbs_per_block)+vdbid);
                    if((fp_vdb = fopen(buf, "r")) == NULL) {
                        perror("vdb_nbits fopen()");
                        exit(EXIT_FAILURE);
                    }
                    cur_nbits = block_nbitsV+(FP_PER_FILE*vdbid);
                    while(fgets(buf, 64, fp_vdb)) {
                        *cur_nbits = atoi(buf);
                        cur_nbits++;
                    }
                    fclose(fp_vdb);
                }

                for(grid_idV=0; grid_idV<grid_per_block; grid_idV++) {
                    for(grid_idH=grid_idV; grid_idH<grid_per_block; grid_idH++) {
                        grid_offsetV = gridsize*grid_idV;
                        grid_offsetH = gridsize*grid_idH;
                        offsetV = (blocksize*block_idV)+grid_offsetV;
                        offsetH = (blocksize*block_idV)+grid_offsetH;
                        grid_vdbV = ((bitshred_t *)block_vdbV)+grid_offsetV;
                        grid_vdbH = ((bitshred_t *)block_vdbV)+grid_offsetH;
                        grid_nbitsV = ((int *)block_nbitsV)+grid_offsetV;
                        grid_nbitsH = ((int *)block_nbitsV)+grid_offsetH;

                        if(grid_idV == grid_idH) {
                            for(file_idV=0; file_idV<gridsize-1; file_idV++) {
                                for(file_idH=file_idV+1; file_idH<gridsize; file_idH++) {
                                    jaccard_ab = jaccard_vdb(grid_vdbV+file_idV, grid_vdbH+file_idH, *(grid_nbitsV+file_idV), *(grid_nbitsH+file_idH));
                                    if(jaccard_ab >= threshold) {
                                        jdb[jid].sid_a = offsetV+file_idV;
                                        jdb[jid].sid_b = offsetH+file_idH;
                                        jdb[jid].sim = jaccard_ab;
                                        jid++;
                                    }
                                    ncmp_per_thread++;
                                }
                            }
                        }
                        else {
                            for(file_idV=0; file_idV<gridsize; file_idV++) {
                                for(file_idH=0; file_idH<gridsize; file_idH++) {
                                    jaccard_ab = jaccard_vdb(grid_vdbV+file_idV, grid_vdbH+file_idH, *(grid_nbitsV+file_idV), *(grid_nbitsH+file_idH));
                                    if(jaccard_ab >= threshold) {
                                        jdb[jid].sid_a = offsetV+file_idV;
                                        jdb[jid].sid_b = offsetH+file_idH;
                                        jdb[jid].sim = jaccard_ab;
                                        jid++;
                                    }

                                    ncmp_per_thread++;
                                }
                            }
                        }
                    }
                }
                block_idV++;
            }
        }
        else {
            block_vdbV = vdb+(tid*blocksize*2);
            block_nbitsV = vdb_nbits+(tid*blocksize*2);
            for (vdbid=0; vdbid<vdbs_per_block; vdbid++) {
                sprintf(buf, "%s/vdb/vdb%05d", db_path, (block_idV*vdbs_per_block)+vdbid);
                if((fp_vdb = fopen(buf, "r")) == NULL) {
                    perror("vdb fopen()");
                    exit(EXIT_FAILURE);
                }
                fread(block_vdbV+(FP_PER_FILE*vdbid), FP_PER_FILE, sizeof(bitshred_t), fp_vdb);
                fclose(fp_vdb);

                sprintf(buf, "%s/vdb/vdb_nbits%05d", db_path, (block_idV*vdbs_per_block)+vdbid);
                if((fp_vdb = fopen(buf, "r")) == NULL) {
                    perror("vdb_nbits fopen()");
                    exit(EXIT_FAILURE);
                }
                cur_nbits = block_nbitsV+(FP_PER_FILE*vdbid);
                while(fgets(buf, 64, fp_vdb)) {
                    *cur_nbits = atoi(buf);
                    cur_nbits++;
                }
                fclose(fp_vdb);
            }

            block_vdbH = vdb+(tid*blocksize*2)+blocksize;
            block_nbitsH = vdb_nbits+(tid*blocksize*2)+blocksize;
            for (vdbid=0; vdbid<vdbs_per_block; vdbid++) {
                sprintf(buf, "%s/vdb/vdb%05d", db_path, (block_idH*vdbs_per_block)+vdbid);
                if((fp_vdb = fopen(buf, "r")) == NULL) {
                    perror("vdb fopen()");
                    exit(EXIT_FAILURE);
                }
                fread(block_vdbH+(FP_PER_FILE*vdbid), FP_PER_FILE, sizeof(bitshred_t), fp_vdb);
                fclose(fp_vdb);

                sprintf(buf, "%s/vdb/vdb_nbits%05d", db_path, (block_idH*vdbs_per_block)+vdbid);
                if((fp_vdb = fopen(buf, "r")) == NULL) {
                    perror("vdb_nbits fopen()");
                    exit(EXIT_FAILURE);
                }
                cur_nbits = block_nbitsH+(FP_PER_FILE*vdbid);
                while(fgets(buf, 64, fp_vdb)) {
                    *cur_nbits = atoi(buf);
                    cur_nbits++;
                }
                fclose(fp_vdb);
            }

            for(grid_idV=0; grid_idV<grid_per_block; grid_idV++) {
                for(grid_idH=0; grid_idH<grid_per_block; grid_idH++) {
                    grid_offsetV = gridsize*grid_idV;
                    grid_offsetH = gridsize*grid_idH;
                    offsetV = (blocksize*block_idV)+grid_offsetV;
                    offsetH = (blocksize*block_idH)+grid_offsetH;
                    grid_vdbV = ((bitshred_t *)block_vdbV)+grid_offsetV;
                    grid_vdbH = ((bitshred_t *)block_vdbH)+grid_offsetH;
                    grid_nbitsV = ((int *)block_nbitsV)+grid_offsetV;
                    grid_nbitsH = ((int *)block_nbitsH)+grid_offsetH;

                    for(file_idV=0; file_idV<gridsize; file_idV++) {
                        for(file_idH=0; file_idH<gridsize; file_idH++) {
                            jaccard_ab = jaccard_vdb(grid_vdbV+file_idV, grid_vdbH+file_idH, *(grid_nbitsV+file_idV), *(grid_nbitsH+file_idH));
                            if (jaccard_ab >= threshold) {
                                jdb[jid].sid_a = offsetV+file_idV;
                                jdb[jid].sid_b = offsetH+file_idH;
                                jdb[jid].sim = jaccard_ab;
                                jid++;
                            }

                            ncmp_per_thread++;
                        }
                    }
                }
            }
        }

        gettimeofday(&time_b, NULL);
        sec_elapsed = time_diff(time_b, time_a);
        bs_verbosemsg("tid %d: Comparing %d (%umin %.3fsec)\n"
               ,tid
               ,ncmp_per_thread
               ,((unsigned int)sec_elapsed / 60), 
               ((sec_elapsed-(unsigned int)sec_elapsed)+(unsigned int)sec_elapsed%60)
               );

        if(jid>0) {
            #pragma omp critical
            jdbid = njdb++;

            sprintf(buf, "%s/jdb/jdb%05d", db_path, jdbid);
            if((fp_jdb = fopen(buf, "w")) == NULL) {
                perror("jdb fopen()");
                exit(EXIT_FAILURE);
            }
            for(i=0; i<jid; i++) {
                fprintf(fp_jdb, "%d:%d:%.3f:\n", jdb[i].sid_a, jdb[i].sid_b, jdb[i].sim);
            }
            fclose(fp_jdb);

            gettimeofday(&time_a, NULL);
            sec_elapsed = time_diff(time_a, time_b);
            bs_verbosemsg("tid %d: Writing to jdb%05d (%umin %.3fsec)\n"
                   ,tid, jdbid
                   ,((unsigned int)sec_elapsed / 60), 
                   ((sec_elapsed-(unsigned int)sec_elapsed)+(unsigned int)sec_elapsed%60)
                   );
        }
        free(jdb);
    } 
    free(cmp_blocks);
    free(vdb);
    free(vdb_nbits);
    return 0;
}

int cluster_vdb(char *db_path, int nsamples, sample_t *jdb_list, int njdb) {
    FILE *fp_cdb = NULL;
    char buf[64];
    int ncluster = 0;
    int *cluster_list;
    unsigned int vid_a, vid_b;
    double jaccard_ab;
    unsigned int i, j;
    unsigned int cid = 0;
    unsigned int tmp_cid = 0;
    unsigned int cnt;
    char *ptr;
    int maxthreads;
    int chunk;

    if((cluster_list = (int *)calloc(nsamples, sizeof(int))) == NULL) {
        perror("cluster_list calloc()");
        exit(EXIT_FAILURE);
    }

    bs_verbosemsg("[-] Clustering with threshold %.3f ...\n", threshold);

    maxthreads = MAX_THREADS;
    omp_set_num_threads(maxthreads);
    chunk = nsamples / maxthreads;

    cid = 1;
    #pragma omp parallel default(shared) private(i,j,buf,ptr,vid_a,vid_b,jaccard_ab,tmp_cid) 
    {
        FILE *fp_jdb = NULL;
        int k;

        #pragma omp for schedule(dynamic,chunk)
        for(k=0; k<njdb; k++) {
            if((fp_jdb = fopen(jdb_list[k].sample_path, "r")) == NULL) {
                perror("jdb fopen()");
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

    sprintf(buf, "%s/cdb_%03u", db_path, (unsigned int)(threshold*100));
    if((fp_cdb = fopen(buf, "w")) == NULL) {
        perror("cdb fopen()"); 
        exit(EXIT_FAILURE);
    }

    for(i=0; i<nsamples; i++) {
        cid = cluster_list[i];
        if(cid == -1) {
            continue;
        }
        else if(cid == 0) {
            cluster_list[i] = -1;
            vid_a = i;
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
                    vid_a = j;
                    fprintf(fp_cdb, "%u ", vid_a);
                    cnt++;
                }
            }
            fprintf(fp_cdb, ":%u:\n", cnt);
        }
    }
    free(cluster_list);
    fclose(fp_cdb);
    return ncluster;
}
