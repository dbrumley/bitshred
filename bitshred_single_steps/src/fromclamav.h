#ifndef __FROMCLAMAV_H__
#define __FROMCLAMAV_H__

#include <unistd.h>
#include <errno.h>
#include "bs_types.h"
#include "pe.h"

extern int debug_flag;
#define cli_dbgmsg (!debug_flag) ? (void)0 : cli_debugmsg
#define cli_errmsg (!debug_flag) ? (void)0 : cli_errormsg

#define CLI_MAX_ALLOCATION (182*1024*1024)

#define CLI_ISCONTAINED(bb, bb_size, sb, sb_size)	\
  ((bb_size) > 0 && (sb_size) > 0 && (size_t)(sb_size) <= (size_t)(bb_size) \
   && (sb) >= (bb) && ((sb) + (sb_size)) <= ((bb) + (bb_size)) && ((sb) + (sb_size)) > (bb) && (sb) < ((bb) + (bb_size)))

#define CLI_ISCONTAINED2(bb, bb_size, sb, sb_size)	\
  ((bb_size) > 0 && (sb_size) >= 0 && (size_t)(sb_size) <= (size_t)(bb_size) \
   && (sb) >= (bb) && ((sb) + (sb_size)) <= ((bb) + (bb_size)) && ((sb) + (sb_size)) >= (bb) && (sb) < ((bb) + (bb_size)))

union unaligned_64 {
	uint64 una_u64;
	int64 una_s64;
} __attribute__((packed));

union unaligned_32 {
	uint32 una_u32;
	int32 una_s32;
} __attribute__((packed));

union unaligned_16 {
	uint16 una_u16;
	int16 una_s16;
} __attribute__((packed));

struct unaligned_ptr {
    void *ptr;
} __attribute__((packed));

#define cli_readint32(buff) (((const union unaligned_32 *)(buff))->una_s32)
#define cli_readint16(buff) (((const union unaligned_16 *)(buff))->una_s16)
#define cli_writeint32(offset, value) (((union unaligned_32 *)(offset))->una_u32=(uint32)(value))

#define CLI_SRS(n,s) ((n)>>(s))
/* #define CLI_SRS(n,s) ((((n)>>(s)) ^ (1<<(sizeof(n)*8-1-s))) - (1<<(sizeof(n)*8-1-s))) */
#define CLI_SAR(n,s) n = CLI_SRS(n,s)

#define EC32(x) x
#define EC16(x) x
#define PEALIGN(o,a) (((a))?(((o)/(a))*(a)):(o))
#define PESALIGN(o,a) (((a))?(((o)/(a)+((o)%(a)!=0))*(a)):(o))


const char *cli_memstr(const char *haystack, unsigned int hs, const char *needle, unsigned int ns);

void cli_debugmsg(char *str);

void cli_errormsg(char *str);
int cli_writen(int fd, const void *buff, unsigned int count);

#endif
