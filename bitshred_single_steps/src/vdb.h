#ifndef __VDB_H__
#define __VDB_H__

#include <stdio.h>
#include <db.h>
#include "bs_common.h"

/* vdb.c */
int update_vdb_bin(DB *dbp, FILE *fp_list, char *filepath, bitshred_t *vdb, int nvirus, int *nfile, uint64_t *t_filesize, uint64_t *t_secsize);
int update_vdb_txt(DB *dbp, FILE *fp_list, char *filepath, bitshred_t *vdb, int nvirus, int *nfile, uint64_t *t_filesize, uint64_t *t_secsize);
int compare_vdb(const char *db_path, int nvirus, int nvirus_added, unsigned int *ncmp);
unsigned int cluster_vdb(int nvirus, const char *db_path);
int neighbor_vdb(DB *dbp, FILE *fp_nn, char *filepath, bitshred_t *vdb, int nvirus, int *nfile, unsigned int *ncmp, uint64_t *t_filesize, uint64_t *t_secsize);
void get_vinfo(const char *db_path, unsigned int vid);

#endif
