#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include "vdb.h"
#include "jaccard.h"
#include "shred.h"

extern double threshold;
extern unsigned int shredsize;
extern unsigned int windowsize;

/* process binary file */
int update_vdb_bin(DB *dbp, FILE *fp_list, char *filepath, bitshred_t *vdb, int nvirus, int *nfile, uint64_t *t_filesize, uint64_t *t_secsize) {
    int i, j;
    int tmp;
    char *ptr;
    bincode_t *bin;
    shred_t *shredp = NULL;
    unsigned int nshred = 0;
    unsigned int filesize = 0;
    unsigned int secsize = 0;
    DBT key, data;
    uint32_t minhash = 0;
    int minid;
    unsigned int nhash;
    int nbits;

    bs_dbgmsg("[%u] %s\n", *nfile+1, filepath);

    /* initialize bincode */
    if((bin = initialize_bincode(filepath)) == NULL) {
        bs_errmsg("[!] %s : skipped (not supported by BFD)\n", filepath);
        return -1;
    }

    /* get shreds from code section */
    nshred = shred_section(bin, &shredp, &filesize, &secsize);
    if (bin != NULL) free_bincode(bin);

    if(nshred < windowsize) {
        fprintf(fp_list, "-\t%s\t0\t0\n", filepath);
        bs_errmsg("[!] %s : skipped (no appropriate sections)\n", filepath);
        free(shredp);
        return -1;
    }

    /* create fingerprint */
    memset(vdb->bit_vector, 0, FP_SIZE);
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
            bit_vector_set(vdb->bit_vector, minhash & (FP_SIZE*8-1));
            nhash++;
        }
        else {
            if(shredp[i+windowsize-1].hash <= minhash) {
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
    bs_dbgmsg("  [-] %d set bits\n", nbits);

    if (nbits > ((FP_SIZE*8)*MAX_SETBITS)) {
        fprintf(fp_list, "-\t%s\t%u\t%u\n", filepath, nshred, nhash);
        bs_errmsg("[!] %s : skipped (too big for the current fingerprint)\n", filepath);
        return -1;
    }
    fprintf(fp_list, "%u\t%s\t%u\t%u\n", nvirus+*nfile+1, filepath, nshred, nhash);

    /* add to DB */
    vdb->nbits = nbits;
    ptr = strrchr(filepath, '/');
    if (ptr)
        strncpy(vdb->file_name, ++ptr, 32);
    else
        strncpy(vdb->file_name, filepath, 32);
    vdb->file_name[32] = '\0';
    memset(&key, 0, sizeof(key));
    memset(&data, 0, sizeof(data));
    data.data = vdb;
    data.size = sizeof(bitshred_t);
    dbp->put(dbp, NULL, &key, &data, DB_APPEND);
    *nfile += 1;

    return nshred;
}

/* process text file */
int update_vdb_txt(DB *dbp, FILE *fp_list, char *filepath, bitshred_t *vdb, int nvirus, int *nfile, uint64_t *t_filesize, uint64_t *t_secsize) {
    int i, j;
    int tmp;
    char *ptr;
    shred_t *shredp = NULL;
    unsigned int nshred = 0;
    DBT key, data;
    uint32_t minhash = 0;
    int minid;
    unsigned int nhash;
    FILE *fp;
    int nbits;
    line_t *linebuffer = NULL;
    unsigned int hash;
    unsigned int offset;

    bs_dbgmsg("[%u] %s\n", *nfile+1, filepath);

    if((fp = fopen(filepath, "r")) == NULL) {
        bs_errmsg("  [!] fopen(): %s\n", filepath);
        exit(EXIT_FAILURE);
    }
    if ((linebuffer = (line_t *)malloc(sizeof(line_t)*shredsize))==NULL) {
        bs_errmsg("  [!] malloc(): linebuffer\n");
        exit(EXIT_FAILURE);
    }

    /* get shreds */
    offset = 0;
    nshred = 0;
    for(j=0; j<shredsize-1; j++) {
        if (!fgets(linebuffer[j].data, MAX_LINEBUF-1, fp)) {
            bs_errmsg("[!] %s : skipped (too small data)\n", filepath);
            free(linebuffer);
            fclose(fp);
            return -1;
        }
        linebuffer[j].offset = offset++;
    }
    while (fgets(linebuffer[shredsize-1].data, MAX_LINEBUF-1, fp)) {
        linebuffer[shredsize-1].offset = offset++;

        djb2_init(&hash);
        for(j=0; j<shredsize; j++) {
            djb2_update(&hash, (unsigned char*)linebuffer[j].data, strlen(linebuffer[j].data));
        }
        if (nshred%1024==0) {
            if((shredp = (shred_t *)realloc(shredp, sizeof(shred_t)*(nshred+1024))) == NULL) {
                bs_errmsg("  [!] realloc(): shredp\n");
                exit(EXIT_FAILURE);
            }
        }
        shredp[nshred].hash = hash;
        shredp[nshred].offset = linebuffer[0].offset;
        nshred++;

        for(j=0; j<shredsize-1; j++) {
            linebuffer[j] = linebuffer[j+1];
        }
    }
    fclose(fp);
    bs_dbgmsg("  [-] %llu shreds\n", nshred);

    if(nshred < windowsize){
        fprintf(fp_list, "-\t%s\t0\t0\n", filepath);
        bs_errmsg("[!] %s : skipped (too small data)\n", filepath);
        free(linebuffer);
        free(shredp);
        return -1;
    }

    /* create fingerprint */
    memset(vdb->bit_vector, 0, FP_SIZE);
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
            bit_vector_set(vdb->bit_vector, minhash & (FP_SIZE*8-1));
            nhash++;
        }
        else {
            if(shredp[i+windowsize-1].hash <= minhash) {
                minhash = shredp[i+windowsize-1].hash;
                minid = i+windowsize-1;
                bit_vector_set(vdb->bit_vector, minhash & (FP_SIZE*8-1));
                nhash++;
            }
        }
    }
    free(linebuffer);
    free(shredp);

    /* count # set bits */
    nbits = 0;
    for(i=0; i<FP_SIZE/4; i++) {
        tmp = ((unsigned int*)(vdb->bit_vector))[i];
        if (tmp) nbits += bitcount(tmp);
    }
    bs_dbgmsg("  [-] %d set bits\n", nbits);

    if (nbits > ((FP_SIZE*8)*MAX_SETBITS)) {
        fprintf(fp_list, "-\t%s\t%u\t%u\n", filepath, nshred, nhash);
        bs_errmsg("[!] %s : skipped (too big for the current fingerprint)\n", filepath);
        return -1;
    }
    fprintf(fp_list, "%u\t%s\t%u\t%u\n", nvirus+*nfile+1, filepath, nshred, nhash);

    /* add to DB */
    vdb->nbits = nbits;
    ptr = strrchr(filepath, '/');
    if (ptr)
        strncpy(vdb->file_name, ++ptr, 32);
    else
        strncpy(vdb->file_name, filepath, 32);
    vdb->file_name[32] = '\0';
    memset(&key, 0, sizeof(key));
    memset(&data, 0, sizeof(data));
    data.data = vdb;
    data.size = sizeof(bitshred_t);
    dbp->put(dbp, NULL, &key, &data, DB_APPEND);
    *nfile += 1;

    return nshred;
}

int compare_vdb(const char *db_path, int nvirus, int nvirus_added, unsigned int *ncmp) {
    DB *vdbp;
    DBT key, data;
    int ret;
    unsigned int vid_a, vid_b;
    bitshred_t *vdb_a = NULL;
    bitshred_t *vdb_b = NULL;
    double jaccard_ab;
    unsigned int i, j, totalcmp;
    FILE *jdbp;
    char buf[64];

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
    sprintf(buf, "%s/jdb", db_path);
    if((jdbp = fopen(buf, "a")) == NULL) {
        bs_errmsg("[!] fopen(): %s\n", buf);
        exit(EXIT_FAILURE);
    }

    if((vdb_a = (bitshred_t *) malloc(sizeof(bitshred_t))) == NULL) {
        bs_errmsg("[!] malloc(): vdb_a\n");
        exit(EXIT_FAILURE);
    }

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

    return 0;
}

unsigned int cluster_vdb(int nfile, const char *db_path) {
    FILE *fp_jdb;
    FILE *fp_cdb;
    char buf[64];
    unsigned int ncluster = 0;
    int *cluster_list;
    unsigned int vid_a, vid_b;
    double jaccard_ab;
    unsigned int index_a, index_b;
    unsigned int i, j;
    unsigned int cid = 0;
    unsigned int tmp_cid = 0;
    unsigned int cnt;
    char *ptr;

    sprintf(buf, "%s/jdb", db_path);
    if((fp_jdb = fopen(buf, "r")) == NULL) {
        bs_errmsg("[!] fopen(): %s\n", buf);
        exit(EXIT_FAILURE);
    }
    sprintf(buf, "%s/cdb_%0.3f", db_path, threshold);
    if((fp_cdb = fopen(buf, "w")) == NULL) {
        bs_errmsg("[!] fopen(): %s\n", buf);
        exit(EXIT_FAILURE);
    }

    if((cluster_list = (int *) calloc(nfile, sizeof(int))) == NULL) {
        bs_errmsg("[!] calloc(): cluster_list\n");
        exit(EXIT_FAILURE);
    }

    /* format of jaccard db file: "vid_a:vid_b:jaccard_ab:" */
    cid = 1;
    while(fgets(buf, 64, fp_jdb) != NULL) {
        ptr = strtok(buf, ":");
        vid_a = atoi(ptr);
        ptr = strtok(NULL, ":");
        vid_b = atoi(ptr);
        ptr = strtok(NULL, ":");
        jaccard_ab = atof(ptr);

        if(jaccard_ab >= threshold) {
            // starting index in berkeley DB = 1 (not 0)
            index_a = vid_a - 1;
            index_b = vid_b - 1;

            if(cluster_list[index_a] == 0 && cluster_list[index_b] == 0) {
                cluster_list[index_a] = cid;
                cluster_list[index_b] = cid;
                cid++;
            }
            else if (cluster_list[index_a] != 0 && cluster_list[index_b] == 0 ){
                cluster_list[index_b] = cluster_list[index_a];
            }
            else if (cluster_list[index_a] == 0 && cluster_list[index_b] != 0 ){
                cluster_list[index_a] = cluster_list[index_b];
            }
            else {
                if (cluster_list[index_a] == cluster_list[index_b])
                    continue;
                else {
                    tmp_cid = cluster_list[index_b];
                    for(i=0; i<nfile; i++) {
                        if(cluster_list[i] == tmp_cid)
                            cluster_list[i] = cluster_list[index_a];
                    }
                }
            }
        }
    }

    for(i=0; i<nfile; i++) {
        cid = cluster_list[i];
        if(cid == -1) {
            continue;
        }
        else if(cid == 0) {
            cluster_list[i] = -1;
            vid_a = i+1;
            ncluster++;

            fprintf(fp_cdb, "%u: %u:1:\n", ncluster, vid_a);
        }
        else {
            cnt = 0;
            ncluster++;
            fprintf(fp_cdb, "%u:", ncluster);
            for(j=i; j<nfile; j++) {
                if(cluster_list[j] == cid) {
                    cluster_list[j] = -1;
                    vid_a = j+1;
                    fprintf(fp_cdb, " %u", vid_a);
                    cnt++;
                }
            }
            fprintf(fp_cdb, ":%u:\n", cnt);
        }
    }
    bs_verbosemsg("done.\n");

    free(cluster_list);
    fclose(fp_jdb);
    fclose(fp_cdb);

    return ncluster;
}

void get_vinfo(const char *db_path, unsigned int vid) {
    DB *dbp;
    DBT key, data;
    int ret;
    bitshred_t *vdb;
    unsigned int bfnum_set = 0, bfnum_clear = 0, bcount = 0;
    unsigned int *arr_ptr;
    char buf[64];

    if((ret = db_create(&dbp, NULL, 0)) != 0){
        bs_errmsg("[!] db_create(): %s\n", db_strerror(ret));
        exit(EXIT_FAILURE);
    }
    sprintf(buf, "%s/vdb", db_path);
    if((ret = dbp->open(dbp, NULL, buf, NULL, DB_RECNO, DB_RDONLY, 0664)) != 0){
        dbp->err(dbp, ret, "[!] %s", buf);
        exit(EXIT_FAILURE);
    }

    memset(&key, 0, sizeof(key));
    memset(&data, 0, sizeof(data));

    key.data = &vid;
    key.size = 4;

    if(dbp->get(dbp, NULL, &key, &data, 0) != DB_NOTFOUND){
        vdb = (bitshred_t *) data.data;

        for(arr_ptr = (unsigned int*) vdb->bit_vector;
            arr_ptr < ((unsigned int*)(vdb->bit_vector + FP_SIZE));
            arr_ptr += 1){
            bcount = bitcount(*arr_ptr);
            bfnum_set += bcount;
            bfnum_clear += (32 - bcount);
        }

        bs_msg("--------------------  VDB INFO  --------------------\n"
               "vid           : %u\n"
               "file_name     : %s\n"
               "# of BF set   : %-8u\n"
               "# of BF clear : %u\n"
               , vid,
               vdb->file_name,
               bfnum_set,
               bfnum_clear
               );
    }
    else{
        bs_msg("[!] not found\n");
    }

    dbp->close(dbp, 0);
}

int neighbor_vdb(DB *vdbp, FILE *fp_nn, char *filepath, bitshred_t *vdb, int nvirus, int *nfile, unsigned int *ncmp, uint64_t *t_filesize, uint64_t *t_secsize) {
    int i, j;
    int tmp;
    bincode_t *bin;
    shred_t *shredp = NULL;
    unsigned int nshred = 0;
    unsigned int filesize = 0;
    unsigned int secsize = 0;
    DBT key, data;
    uint32_t minhash = 0;
    int minid;
    unsigned int nhash;
    int vid_b;
    bitshred_t *vdb_b;
    double jaccard_ab;
    double max_jaccard;
    int max_vid;
    int nbits;

    bs_dbgmsg("[%u] %s\n", *nfile+1, filepath);

    /* initialize bincode */
    if((bin = initialize_bincode(filepath)) == NULL) {
        bs_errmsg("[!] %s : skipped (not supported by BFD)\n", filepath);
        return -1;
    }

    /* get shreds from code section */
    nshred = shred_section(bin, &shredp, &filesize, &secsize);
    if (bin != NULL) free_bincode(bin);

    if(nshred < windowsize){
        bs_errmsg("[!] %s : skipped (no appropriate sections)\n", filepath);
        free(shredp);
        return -1;
    }

    /* create fingerprint */
    memset(vdb->bit_vector, 0, FP_SIZE);
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
            bit_vector_set(vdb->bit_vector, minhash & (FP_SIZE*8-1));
            nhash++;
        }
        else {
            if(shredp[i+windowsize-1].hash <= minhash) {
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
    vdb->nbits = nbits;
    bs_dbgmsg("  [-] %d set bits\n", nbits);

    max_jaccard = 0;
    max_vid = 0;
    for(i=0; i<nvirus; i++) {
        vid_b = i+1;
        memset(&key, 0, sizeof(key));
        memset(&data, 0, sizeof(data));
        key.data = &vid_b;
        key.size = 4;
        vdbp->get(vdbp, NULL, &key, &data, 0);
        vdb_b = (bitshred_t *)data.data;
        jaccard_ab = jaccard_vdb(vdb, vdb_b);
        if (jaccard_ab > max_jaccard) {
            max_jaccard = jaccard_ab;
            max_vid = vid_b;
        }
        *ncmp += 1;
    }
    fprintf(fp_nn, "%s: %d (%.3f)\n", filepath, max_vid, max_jaccard);
    *nfile += 1;

    return 0;
}
