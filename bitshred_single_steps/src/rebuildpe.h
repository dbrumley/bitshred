#ifndef __REBUILDPE_H
#define __REBUILDPE_H

#include <stdio.h>
#include "bs_types.h"
#include "pe.h"

int cli_rebuildpe(char *, struct exe_section *, int, uint32, uint32, uint32, uint32, int);

#endif
