#include "bs_common.h"

int ccgen_helper(sample_t *sample, bitshred_t *bs_fp, int tid, int chunk, int offset) {
    int i, j, k;
    int nshred = 0;
    uint32_t minhash = 0;
    uint32_t tmphash = 0;
    int minid;
    unsigned int nhash;
    bitshred_t *sample_bs_fp = NULL;
    unsigned char *section_data = NULL;
    unsigned char buf[8];
    FILE *fp;

    if((fp = fopen(sample->sample_path, "r")) == NULL){
        perror("fp fopen()");
        exit(EXIT_FAILURE);
    }
    sample->sample_id = tid*chunk + offset;

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
                nshred = sectionSize - (shredsize-1);
                if(sectionSize < shredsize || nshred < windowsize){
                    bs_verbosemsg("[!] Invalid section size: %s\n", sample->sample_path);
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
                        bs_verbosemsg("[!] Corrupted header: %s\n", sample->sample_path);
                        free(section_data);
                        fclose(fp);
                        return -1;
                    }
                }
                break;
            }
        }

        if (section_data != NULL) {
            sample_bs_fp = bs_fp+offset;
            bs_init(sample_bs_fp);
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
                    bit_vector_set(sample_bs_fp->bit_vector, minhash & (FP_SIZE*8-1));
                    nhash++;
                }
                else {
                    tmphash = djb2(section_data+(i+windowsize-1));
                    if(tmphash <= minhash) {
                        minhash = tmphash;
                        minid = i+windowsize-1;
                        bit_vector_set(sample_bs_fp->bit_vector, minhash & (FP_SIZE*8-1));
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

int ccgen(char *db_path, sample_t *sample_list) {
    FILE *fp;
    char buf[64];
    int tid;
    int chunk;
    int k;

    chunk = nsamples/row_max_threads;
    omp_set_num_threads(row_max_threads);
    bs_msg("[ccgen] %d samples, %d row_threads (row_chunk: %d)/ %d col_threads\n", nsamples, row_max_threads, chunk, col_max_threads);

    /* first touch */
    #pragma omp parallel default(shared) private(tid)
    {
        tid = omp_get_thread_num();
        memset(bs_fp+(tid*chunk), 0, sizeof(bitshred_t)*chunk);
    }

    #pragma omp parallel default(shared) private(tid,buf,fp)
    {
        int i = 0;
        int nproc_per_thread = 0;
        bitshred_t *thread_bs_fp;
        tid = omp_get_thread_num();

        thread_bs_fp = bs_fp+(tid*chunk);

        //create fingerprints
        #pragma omp for schedule(static,chunk) nowait
        for(i=0; i<nsamples; i++) {
            ccgen_helper(sample_list+i, thread_bs_fp, tid, chunk, nproc_per_thread);
            nproc_per_thread++;
        }
        sprintf(buf, "%s/adjlist/data%d", db_path, tid);
        if((fp=fopen(buf, "w"))==NULL) {
            perror("data fopen()");
            exit(EXIT_FAILURE);
        }
        fwrite(thread_bs_fp, sizeof(bitshred_t), chunk, fp);
        fclose(fp);
    }

    sprintf(buf, "%s/cclist.log", db_path);
    if((fp=fopen(buf, "w"))==NULL) {
        perror("cclist fopen()");
        exit(EXIT_FAILURE);
    }
    for(k=0; k<nsamples; k++) {
        fprintf(fp, "%d\t%s\n", sample_list[k].sample_id, sample_list[k].sample_path);
    }
    fclose(fp);
    return 0;
}

int ccread(char *db_path, sample_t *sample_list, int fp_per_file) {
    int tid;
    int chunk;
    int i = 0;
    FILE *fp;

    chunk = nsamples/row_max_threads;
    omp_set_num_threads(row_max_threads);
    bs_msg("[ccread] %d samples, %d row_max_threads (row_chunk: %d)/ %d col_max_threads\n", nsamples, row_max_threads, chunk, col_max_threads);

    #pragma omp parallel default(shared) private(tid)
    {
        tid = omp_get_thread_num();
        memset(bs_fp+(tid*chunk), 0, sizeof(bitshred_t)*chunk);
    }

    //read adjacent lists
    for(i=0; i<(nsamples/fp_per_file); i++) {
        if((fp=fopen(sample_list[i].sample_path, "r"))==NULL) {
            perror("data fopen()");
            exit(EXIT_FAILURE);
        }
        if(fp_per_file!=(fread(bs_fp+(i*fp_per_file), sizeof(bitshred_t), fp_per_file, fp))) {
            perror("fread data");
            exit(EXIT_FAILURE);
        }
        fclose(fp);
    }
    return 0;
}

int ccgen_ascii(char *db_path, sample_t *sample_list) {
    FILE *fp;
    char buf[64];
    int tid;
    int chunk;
    int k;
    char outbuf[FP_SIZE*8+1];
    int idx;
    uint32_t byteIndex;
    uint8_t bitMask;

    chunk = nsamples/row_max_threads;
    omp_set_num_threads(row_max_threads);
    bs_msg("[ccgen_ascii] %d samples, %d row_threads (row_chunk: %d)\n", nsamples, row_max_threads, chunk);

    /* first touch */
    #pragma omp parallel default(shared) private(tid)
    {
        tid = omp_get_thread_num();
        memset(bs_fp+(tid*chunk), 0, sizeof(bitshred_t)*chunk);
    }

    #pragma omp parallel default(shared) private(tid,buf,fp)
    {
        int i = 0;
        int nproc_per_thread = 0;
        bitshred_t *thread_bs_fp;
        tid = omp_get_thread_num();

        thread_bs_fp = bs_fp+(tid*chunk);

        //create fingerprints
        #pragma omp for schedule(static,chunk) nowait
        for(i=0; i<nsamples; i++) {
            ccgen_helper(sample_list+i, thread_bs_fp, tid, chunk, nproc_per_thread);
            nproc_per_thread++;
        }
        sprintf(buf, "%s/adjlist/data%d", db_path, tid);
        if((fp=fopen(buf, "w"))==NULL) {
            perror("data fopen()");
            exit(EXIT_FAILURE);
        }
        fwrite(thread_bs_fp, sizeof(bitshred_t), chunk, fp);
        fclose(fp);
    }

    sprintf(buf, "%s/data_ascii.log", db_path);
    if((fp=fopen(buf, "w"))==NULL) {
        perror("data_ascii fopen()");
        exit(EXIT_FAILURE);
    }
    for(idx=0; idx<nsamples; idx++) {
        for(k=0; k<FP_SIZE*8; k++) {
            byteIndex = k >> 3;
            bitMask = 1 << (k & 0x00000007);
            if ((bs_fp+idx)->bit_vector[byteIndex] & bitMask) {
                outbuf[k] = '1';
            }
            else {
                outbuf[k] = '0';
            }
        }
        outbuf[k] = '\0';
        fprintf(fp, "%s\n", outbuf);
    }
    fclose(fp);

    sprintf(buf, "%s/cclist.log", db_path);
    if((fp=fopen(buf, "w"))==NULL) {
        perror("cclist fopen()");
        exit(EXIT_FAILURE);
    }
    for(k=0; k<nsamples; k++) {
        fprintf(fp, "%d\t%s\n", sample_list[k].sample_id, sample_list[k].sample_path);
    }
    fclose(fp);
    return 0;
}
