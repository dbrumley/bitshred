#ifndef __VDB_H__
#define __VDB_H__

#include <stdio.h>
#include "bs_common.h"

/* vdb.c */
int update_vdb(char *db_path, sample_t *sample_list, int nsamples);
int compare_vdb(char *db_path, int nsamples);
int cluster_vdb(char *db_path, int nsamples, sample_t *jdb_list, int njdb);

#endif
