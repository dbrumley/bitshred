#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <fts.h>

#include "vdb.h"
#include "jaccard.h"
#include "shred.h"

extern double threshold;
extern unsigned int shredsize;
extern unsigned int windowsize;

/* process binary file */
int update_vdb_bin(char *filepath, FILE *fp_list, bitshred_t *vdb, unsigned int nblock, unsigned int *nfile, uint64_t *t_filesize, uint64_t *t_secsize) {
    int i, j;
    int tmp;
    bincode_t *bin;
    shred_t *shredp = NULL;
    unsigned int nshred = 0;
    unsigned int filesize = 0;
    unsigned int secsize = 0;
    uint32_t minhash = 0;
    int minid;
    unsigned int nhash;
    unsigned int nbits;

    bs_dbgmsg(" (%u) %s\n", nblock*FP_PER_BLOCK+*nfile, filepath);

    /* initialize bincode */
    if ((bin = initialize_bincode(filepath)) == NULL) {
        bs_errmsg("  (!) %s : skipped (not supported by BFD)\n", filepath);
        return -1;
    }

    /* get shreds from code section */
    nshred = shred_section(bin, &shredp, &filesize, &secsize);
    if (bin != NULL) free_bincode(bin);

    if (nshred < windowsize) {
        bs_errmsg("  (!) %s : skipped (no appropriate sections)\n", filepath);
        free(shredp);
        return -1;
    }

    /* create fingerprint */
    memset(vdb->bit_vector, 0, FP_SIZE);
    nhash = 0;
    minid = -1;
    for (i=0; i<(nshred-windowsize+1); i++) {
        if (minid < i) {
            minhash = shredp[i].hash;
            minid = i;
            for (j=1; j<windowsize; j++) {
                if(shredp[i+j].hash <= minhash) {
                    minhash = shredp[i+j].hash;
                    minid = i+j;
                }
            }
            bit_vector_set(vdb->bit_vector, minhash & (FP_SIZE*8-1));
            nhash++;
        }
        else {
            if (shredp[i+windowsize-1].hash <= minhash) {
                minhash = shredp[i+windowsize-1].hash;
                minid = i+windowsize-1;
                bit_vector_set(vdb->bit_vector, minhash & (FP_SIZE*8-1));
                nhash++;
            }
        }
    }
    *t_filesize += filesize;
    *t_secsize += secsize;
    free(shredp);

    /* count # set bits */
    nbits = 0;
    for(i=0; i<FP_SIZE/4; i++) {
        tmp = ((unsigned int*)(vdb->bit_vector))[i];
        if (tmp) nbits += bitcount(tmp);
    }
    bs_dbgmsg("  + # set bits: %u\n", nbits);

    if (nbits > ((FP_SIZE*8)*MAX_SETBITS)) {
        fprintf(fp_list, "-\t%s\t%u\t%u\n", filepath, nshred, nhash);
        bs_errmsg("  (!) %s : skipped (too big to fit into the current fingerprint)\n", filepath);
        return -1;
    }
    fprintf(fp_list, "%u\t%s\t%u\t%u\n", (nblock*FP_PER_BLOCK+*nfile), filepath, nshred, nhash);

    vdb->nbits = nbits;
    *nfile += 1;

    return nhash;
}

/* process text file */
int update_vdb_txt(char *filepath, FILE *fp_list, bitshred_t *vdb, unsigned int nblock, unsigned int *nfile) {
    int i, j;
    int tmp;
    shred_t *shredp = NULL;
    unsigned int nshred = 0;
    uint32_t minhash = 0;
    int minid;
    unsigned int nhash;
    FILE *fp;
    unsigned int nbits;

    bs_dbgmsg(" (%u) %s\n", nblock*FP_PER_BLOCK+*nfile, filepath);

    if ((fp = fopen(filepath, "r")) == NULL) {
        bs_errmsg("  (!) fopen(): %s\n", filepath);
        return -1;
    }

    /* get shreds */
    nshred = shred_txt(fp, &shredp);
    fclose(fp);

    if(nshred < windowsize){
        bs_errmsg("  (!) %s : skipped (too small data)\n", filepath);
        free(shredp);
        return -1;
    }

    /* create fingerprint */
    memset(vdb->bit_vector, 0, FP_SIZE);
    nhash = 0;
    minid = -1;
    for (i=0; i<(nshred-windowsize+1); i++){
        if (minid < i) {
            minhash = shredp[i].hash;
            minid = i;
            for (j=1; j<windowsize; j++) {
                if (shredp[i+j].hash <= minhash) {
                    minhash = shredp[i+j].hash;
                    minid = i+j;
                }
            }
            bit_vector_set(vdb->bit_vector, minhash & (FP_SIZE*8-1));
            nhash++;
        }
        else {
            if (shredp[i+windowsize-1].hash <= minhash) {
                minhash = shredp[i+windowsize-1].hash;
                minid = i+windowsize-1;
                bit_vector_set(vdb->bit_vector, minhash & (FP_SIZE*8-1));
                nhash++;
            }
        }
    }
    free(shredp);

    /* count # set bits */
    nbits = 0;
    for(i=0; i<FP_SIZE/4; i++) {
        tmp = ((unsigned int*)(vdb->bit_vector))[i];
        if (tmp) nbits += bitcount(tmp);
    }
    bs_dbgmsg("  + # set bits: %u\n", nbits);

    if (nbits > ((FP_SIZE*8)*MAX_SETBITS)) {
        fprintf(fp_list, "-\t%s\t%u\t%u\n", filepath, nshred, nhash);
        bs_errmsg("  (!) %s : skipped (too big to fit into the current fingerprint)\n", filepath);
        return -1;
    }
    fprintf(fp_list, "%u\t%s\t%u\t%u\n", (nblock*FP_PER_BLOCK+*nfile), filepath, nshred, nhash);

    vdb->nbits = nbits;
    *nfile += 1;

    return nhash;
}

/* update database */
unsigned int update_vdb(char *db_path, char *input_path, int exe_inst) {
    FTS *ftsp;
    FTSENT *p, *chp;
    int fts_options = FTS_NOSTAT | FTS_COMFOLLOW | FTS_PHYSICAL;
    char *target[2];
    DB *dbp;
    DBT key, data;
    int ret;
    bitshred_t *vdb = NULL;
    FILE *fp = NULL;
    unsigned int nblock = 0;
    unsigned int nfile = 0;
    uint64_t t_filesize = 0;
    uint64_t t_secsize = 0;
    struct timeval t_stime, t_etime;
    double sec_elapsed = 0;
    char buf[1024];
    unsigned int nvirus = 0;

    gettimeofday(&t_stime, NULL);

    sprintf(buf, "%s", db_path);
    if (access(buf, F_OK))
        mkdir(buf, S_IRWXU|S_IXGRP|S_IRGRP|S_IROTH|S_IXOTH);

    /* initialize ftsp */
    target[0] = input_path;
    target[1] = NULL;
    if ((ftsp = fts_open(target, fts_options, NULL)) == NULL) {
        bs_errmsg("[!] fts_open(): %s\n", input_path);
        exit(EXIT_FAILURE);
    }
    if ((chp = fts_children(ftsp, 0)) == NULL) {
        return -1;   // no files to traverse
    }

    /* open DB */
    if ((ret = db_create(&dbp, NULL, 0)) != 0){
        bs_errmsg("[!] db_create(): %s\n", db_strerror(ret));
        exit(EXIT_FAILURE);
    }
    sprintf(buf, "%s/vdb.db", db_path);
    if ((ret = dbp->open(dbp, NULL, buf, NULL, DB_RECNO, DB_CREATE | DB_TRUNCATE, 0664)) != 0){
        dbp->err(dbp, ret, "[!] %s", buf);
        exit(EXIT_FAILURE);
    }

    /* list of input files */
    sprintf(buf, "%s/vdb_list.txt", db_path);
    if ((fp = fopen(buf, "w")) == NULL) {
        bs_errmsg("[!] fopen(): %s\n", buf);
        exit(EXIT_FAILURE);
    }
    fprintf(fp, "#vid\tfilepath\tnshred\tnhash\n");

    if ((vdb = (bitshred_t *)malloc(sizeof(bitshred_t)*FP_PER_BLOCK)) == NULL){
        bs_errmsg("[!] malloc(): vdb\n");
        exit(EXIT_FAILURE);
    }

    bs_verbosemsg("[-] updating database (shred: %u, window: %u)\n", shredsize, windowsize);

    /* traverse input path */
    if (exe_inst == EXE_BIN) {    // binary files
        while ((p = fts_read(ftsp)) != NULL) {
            switch (p->fts_info) {
            case FTS_F:
            case FTS_NSOK:
                update_vdb_bin(p->fts_name, fp, vdb+nfile, nblock, &nfile, &t_filesize, &t_secsize);
                break;
            default:
                break;
            }

            if (nfile == FP_PER_BLOCK) {
                bs_dbgmsg(" ((( writing to db: %u )))\n", nfile);
                /* add to DB */
                memset(&key, 0, sizeof(key));
                memset(&data, 0, sizeof(data));
                data.data = vdb;
                data.size = sizeof(bitshred_t)*FP_PER_BLOCK;
                dbp->put(dbp, NULL, &key, &data, DB_APPEND);
                nfile = 0;
                nblock++;
            }
        }
    }
    else if (exe_inst == EXE_TXT) {   // text files
        while ((p = fts_read(ftsp)) != NULL) {
            switch (p->fts_info) {
            case FTS_F:
            case FTS_NSOK:
                update_vdb_txt(p->fts_name, fp, vdb+nfile, nblock, &nfile);
                break;
            default:
                break;
            }

            if (nfile == FP_PER_BLOCK) {
                bs_dbgmsg(" ((( writing to db: %u )))\n", nfile);
                /* add to DB */
                memset(&key, 0, sizeof(key));
                memset(&data, 0, sizeof(data));
                data.data = vdb;
                data.size = sizeof(bitshred_t)*FP_PER_BLOCK;
                dbp->put(dbp, NULL, &key, &data, DB_APPEND);
                nfile = 0;
                nblock++;
            }
        }
    }
    if (nfile > 0) {
        bs_dbgmsg(" ((( writing to db: %u )))\n", nfile);
        /* add to DB */
        memset(&key, 0, sizeof(key));
        memset(&data, 0, sizeof(data));
        data.data = vdb;
        data.size = sizeof(bitshred_t)*FP_PER_BLOCK;
        dbp->put(dbp, NULL, &key, &data, DB_APPEND);
        nblock++;
    }
    nvirus = (nblock==0) ? 0 : (nblock-1)*FP_PER_BLOCK + nfile;

    /* close DB */
    dbp->close(dbp, 0);
    fts_close(ftsp);
    free(vdb);
    fclose(fp);

    gettimeofday(&t_etime, NULL);
    sec_elapsed = time_diff(t_etime, t_stime);

    bs_verbosemsg("[-] %u files (%um %.3fs)\n",
        nvirus,
        ((unsigned int)sec_elapsed / 60),
        ((sec_elapsed-(unsigned int)sec_elapsed)+(unsigned int)sec_elapsed%60));

    if (exe_inst == EXE_BIN) {
        bs_verbosemsg("[-] file size: %.2f MiB, section size: %.2f MiB (executable)\n",
           (double)t_filesize/(1024*1024),
           (double)t_secsize/(1024*1024));
    }

    return nvirus;
}

/* cluster database */
unsigned int cluster_vdb(const char *db_path, unsigned int nvirus) {
    DB *vdbp;
    DBT key, data;
    int ret;
    unsigned int vid_a, vid_b;
    double jaccard_ab;
    unsigned int i, j, totalcmp;
    FILE *cdbp;
    char buf[1024];
    struct timeval t_stime, t_etime;
    double sec_elapsed = 0;
    unsigned int nblock;
    unsigned int nfile;
    unsigned int db_key;
    unsigned int ncluster = 0;
    unsigned int cid = 0;
    unsigned int tmp_cid = 0;
    int *cluster_list;
    unsigned int block_idV, block_idH;
    bitshred_t *block_vdbV, *block_vdbH;
    unsigned int blocksizeV, blocksizeH;
    unsigned int file_idV, file_idH;
    unsigned int ncmp = 0;
    unsigned int last_block;
    bitshred_t *vdb;

    gettimeofday(&t_stime, NULL);

    /* open DB */
    if ((ret = db_create(&vdbp, NULL, 0)) != 0){
        bs_errmsg("[!] db_create(): %s\n", db_strerror(ret));
        exit(EXIT_FAILURE);
    }
    sprintf(buf, "%s/vdb.db", db_path);
    if ((ret = vdbp->open(vdbp, NULL, buf, NULL, DB_RECNO, DB_RDONLY, 0664)) != 0){
        vdbp->err(vdbp, ret, "[!] %s", buf);
        exit(EXIT_FAILURE);
    }

    nfile = nvirus % FP_PER_BLOCK;
    if (nfile == 0) {
        nblock = nvirus/FP_PER_BLOCK;
        last_block = FP_PER_BLOCK;
    }
    else {
        nblock = (nvirus/FP_PER_BLOCK)+1;
        last_block = nfile;
    }

    if ((vdb = (bitshred_t *)malloc(sizeof(bitshred_t)*FP_PER_BLOCK)) == NULL){
        bs_errmsg("[!] malloc(): vdb\n");
        exit(EXIT_FAILURE);
    }
    if ((cluster_list = (int *)calloc(nvirus, sizeof(int))) == NULL) {
        bs_errmsg("[!] calloc(): cluster_list\n");
        exit(EXIT_FAILURE);
    }
    totalcmp = (nvirus*(nvirus-1))/2;

    bs_verbosemsg("\n[-] clustering database (t: %.3f)     ", threshold);

    /* measure pairwise similarity & perform clustering */
    cid = 1;
    for (block_idV=0; block_idV<nblock; block_idV++) {
        for (block_idH=block_idV; block_idH<nblock; block_idH++) {
            if (block_idV == block_idH) {
                db_key = block_idV+1;
                memset(&key, 0, sizeof(key));
                memset(&data, 0, sizeof(data));
                key.data = &db_key;
                key.size = 4;
                vdbp->get(vdbp, NULL, &key, &data, 0);
                block_vdbV = (bitshred_t *)data.data;
                block_vdbH = block_vdbV;
                blocksizeV = (block_idV==nblock-1) ? last_block : FP_PER_BLOCK;
                blocksizeH = blocksizeV;

                for (file_idV=0; file_idV<blocksizeV-1; file_idV++) {
                    for (file_idH=file_idV+1; file_idH<blocksizeH; file_idH++) {
                        jaccard_ab = jaccard_vdb(block_vdbV+file_idV, block_vdbH+file_idH);
                        if (jaccard_ab >= threshold) {
                            vid_a = FP_PER_BLOCK*block_idV + file_idV;
                            vid_b = FP_PER_BLOCK*block_idH + file_idH;

                            if (cluster_list[vid_a]==0 && cluster_list[vid_b]==0) {
                                cluster_list[vid_a] = cid;
                                cluster_list[vid_b] = cid;
                                cid++;
                            }
                            else if (cluster_list[vid_a]!=0 && cluster_list[vid_b]==0 ) {
                                cluster_list[vid_b] = cluster_list[vid_a];
                            }
                            else if (cluster_list[vid_a]==0 && cluster_list[vid_b]!=0) {
                                cluster_list[vid_a] = cluster_list[vid_b];
                            }
                            else {
                                if (cluster_list[vid_a] != cluster_list[vid_b]) {
                                    tmp_cid = cluster_list[vid_b];
                                    for (i=0; i<nvirus; i++) {
                                        if (cluster_list[i] == tmp_cid)
                                            cluster_list[i] = cluster_list[vid_a];
                                    }
                                }
                            }
                        }
                        ncmp++;
                        if (ncmp%100 == 0) bs_verbosemsg("\b\b\b\b%3.0f%%", ncmp/(totalcmp*0.01));
                    }
                }
            }
            else {
                db_key = block_idV+1;
                memset(&key, 0, sizeof(key));
                memset(&data, 0, sizeof(data));
                key.data = &db_key;
                key.size = 4;
                vdbp->get(vdbp, NULL, &key, &data, 0);
                memcpy(vdb, data.data, data.size);
                block_vdbV = vdb;
                blocksizeV = (block_idV==nblock-1) ? last_block : FP_PER_BLOCK;

                db_key = block_idH+1;
                memset(&key, 0, sizeof(key));
                memset(&data, 0, sizeof(data));
                key.data = &db_key;
                key.size = 4;
                vdbp->get(vdbp, NULL, &key, &data, 0);
                block_vdbH = (bitshred_t *)data.data;
                blocksizeH = (block_idH==nblock-1) ? last_block : FP_PER_BLOCK;

                for (file_idV=0; file_idV<blocksizeV; file_idV++) {
                    for (file_idH=0; file_idH<blocksizeH; file_idH++) {
                        jaccard_ab = jaccard_vdb(block_vdbV+file_idV, block_vdbH+file_idH);
                        if (jaccard_ab >= threshold) {
                            vid_a = FP_PER_BLOCK*block_idV + file_idV;
                            vid_b = FP_PER_BLOCK*block_idH + file_idH;

                            if (cluster_list[vid_a]==0 && cluster_list[vid_b]==0) {
                                cluster_list[vid_a] = cid;
                                cluster_list[vid_b] = cid;
                                cid++;
                            }
                            else if (cluster_list[vid_a]!=0 && cluster_list[vid_b]==0 ) {
                                cluster_list[vid_b] = cluster_list[vid_a];
                            }
                            else if (cluster_list[vid_a]==0 && cluster_list[vid_b]!=0) {
                                cluster_list[vid_a] = cluster_list[vid_b];
                            }
                            else {
                                if (cluster_list[vid_a] != cluster_list[vid_b]) {
                                    tmp_cid = cluster_list[vid_b];
                                    for (i=0; i<nvirus; i++) {
                                        if (cluster_list[i] == tmp_cid)
                                            cluster_list[i] = cluster_list[vid_a];
                                    }
                                }
                            }
                        }
                        ncmp++;
                        if (ncmp%100 == 0) bs_verbosemsg("\b\b\b\b%3.0f%%", ncmp/(totalcmp*0.01));
                    }
                }
            }
        }
    }
    bs_verbosemsg("\b\b\b\b100%%\n");
    bs_dbgmsg("  + # blocks: %u (last_block: %u)\n", nblock, last_block);
    bs_dbgmsg("  + # comparisons: %u\n", ncmp);
    vdbp->close(vdbp, 0);
    free(vdb);

    sprintf(buf, "%s/cdb_%0.3f.txt", db_path, threshold);
    if ((cdbp = fopen(buf, "w")) == NULL) {
        bs_errmsg("[!] fopen(): %s\n", buf);
        exit(EXIT_FAILURE);
    }

    bs_verbosemsg("[-] outputting results (%s)\n", buf);

    for (i=0; i<nvirus; i++) {
        cid = cluster_list[i];
        if (cid == -1) continue;

        if (cid == 0) {
            cluster_list[i] = -1;
            fprintf(cdbp, "C%u: %u\n", ncluster, i);
            ncluster++;
        }
        else {
            fprintf(cdbp, "C%u:", ncluster);
            for (j=i; j<nvirus; j++) {
                if (cluster_list[j] == cid) {
                    cluster_list[j] = -1;
                    fprintf(cdbp, " %u", j);
                }
            }
            fprintf(cdbp, "\n");
            ncluster++;
        }
    }
    free(cluster_list);
    fclose(cdbp);

    gettimeofday(&t_etime, NULL);
    sec_elapsed = time_diff(t_etime, t_stime);

    bs_verbosemsg("[-] %u clusters (%um %.3fs)\n",
        ncluster,
        ((unsigned int)sec_elapsed / 60),
        ((sec_elapsed-(unsigned int)sec_elapsed)+(unsigned int)sec_elapsed%60));

    return ncluster;
}
