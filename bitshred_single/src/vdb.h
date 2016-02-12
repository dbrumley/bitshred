#ifndef __VDB_H__
#define __VDB_H__

#include <stdio.h>
#include <db.h>
#include "bs_common.h"

/* vdb.c */
unsigned int update_vdb(char *db_path, char *input_path, int exe_inst);
unsigned int cluster_vdb(const char *db_path, unsigned int nvirus);

#endif
