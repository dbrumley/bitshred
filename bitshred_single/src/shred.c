#include "shred.h"
#include "bs_common.h"

extern unsigned int shredsize;

int shred_data(shred_t **shredp, unsigned char *pdata, bfd_size_type secshred, bfd_size_type nshred, bfd_size_type index) {
    size_t offset;
    bfd_size_type i;
    unsigned int j;
    char *inst_seq;

    if((inst_seq = (char *)malloc(shredsize * sizeof(char))) == NULL) {
        bs_errmsg("  (!) malloc(): inst_seq\n");
        exit(EXIT_FAILURE);
    }

    offset = 0 ;
    for(i=0;i<secshred;i++) {
        for(j=0;j<shredsize;j++)
            inst_seq[j] = *(pdata+j);

        (*shredp)[index].hash = djb2((unsigned char *)inst_seq);
        (*shredp)[index].offset = offset;

        pdata++;
        index++;
        offset++;
    }
    bs_dbgmsg("  + # shreds: %llu\n", secshred);

    free(inst_seq);
    return 0;
}

/* shred section data */
int shred_section(bincode_t *bin, shred_t **shredp, unsigned int *filesize, unsigned int *secsize) {
    bfd_size_type nshred, size, secshred, index; // BFD_HOST_U_64_BIT
    bfd_vma vma, offset;
    bfd_vma entry;
    bfd_byte *pdata;
    struct section *sec;

    size = 0;
    nshred = 0;
    index = 0;
    entry = bfd_get_start_address(bin->abfd);
    sec = bin->sec;
    while(sec) {
        /* process the executable section located at entry point */
        /* process the section whose name is .text or CODE */
        if ((!sec->is_code || entry < sec->vma || entry >= (sec->vma+sec->datasize)) &&
            (strcmp(sec->name, ".text")!=0 && strcmp(sec->name, "CODE")!=0)) {
            sec = sec->next;
            continue;
        }

        if(sec->datasize < shredsize) {
            bs_dbgmsg("  (!) %s : invalid size\n", sec->name);
            sec = sec->next;
            continue;
        }
        bs_dbgmsg("  + section: %s\n", sec->name);

        secshred = sec->datasize - (shredsize-1);
        nshred += secshred;
        size += sec->datasize;
        vma = sec->vma;

        if((*shredp = (shred_t *)realloc(*shredp, sizeof(shred_t) * nshred)) == NULL) {
            bs_errmsg("  (!) realloc(): shredp\n");
            exit(EXIT_FAILURE);
        }
        pdata = sec->data;
        offset = 0;

	shred_data(shredp, pdata, secshred, nshred, index);

        sec = sec->next;
    }

    *filesize = bin->filesize;
    *secsize = size;
    return nshred;
}

/* shred text data */
int shred_txt(FILE *fp, shred_t **shredp) {
    int i;
    unsigned int offset;
    unsigned int nshred = 0;
    line_t *linebuffer = NULL;
    unsigned int hash;

    if ((linebuffer = (line_t *)malloc(sizeof(line_t)*shredsize))==NULL) {
        bs_errmsg("  (!) malloc(): linebuffer\n");
        exit(EXIT_FAILURE);
    }

    offset = 0;
    nshred = 0;
    for (i=0; i<shredsize-1; i++) {
        if (!fgets(linebuffer[i].data, MAX_LINEBUF-1, fp)) {
            free(linebuffer);
            return -1;
        }
        linebuffer[i].offset = offset++;
    }
    while (fgets(linebuffer[shredsize-1].data, MAX_LINEBUF-1, fp)) {
        linebuffer[shredsize-1].offset = offset++;

        djb2_init(&hash);
        for (i=0; i<shredsize; i++) {
            djb2_update(&hash, (unsigned char*)linebuffer[i].data, strlen(linebuffer[i].data));
        }
        if (nshred%1024 == 0) {
            if((*shredp = (shred_t *)realloc(*shredp, sizeof(shred_t)*(nshred+1024))) == NULL) {
                bs_errmsg("  (!) realloc(): shredp\n");
                exit(EXIT_FAILURE);
            }
        }
        (*shredp)[nshred].hash = hash;
        (*shredp)[nshred].offset = linebuffer[0].offset;
        nshred++;

        for(i=0; i<shredsize-1; i++) {
            linebuffer[i] = linebuffer[i+1];
        }
    }
    free(linebuffer);
    bs_dbgmsg("  + # shreds: %u\n", nshred);

    return nshred;
}
