#include <stdlib.h>

#include "bs_types.h"
#include "rebuildpe.h"

#include "fsg.h"

static int doubledl(char **scur, uint8 *mydlptr, char *buffer, uint32 buffersize)
{
  unsigned char mydl = *mydlptr;
  unsigned char olddl = mydl;

  mydl*=2;
  if ( !(olddl & 0x7f)) {
    if ( *scur < buffer || *scur >= buffer+buffersize-1 )
      return -1;
    olddl = **scur;
    mydl = olddl*2+1;
    *scur=*scur + 1;
  }
  *mydlptr = mydl;
  return (olddl>>7)&1;
}


int cli_unfsg(char *source, char *dest, int ssize, int dsize, char **endsrc, char **enddst) {
  uint8 mydl=0x80;
  uint32 backbytes, backsize, oldback = 0;
  char *csrc = source, *cdst = dest;
  int oob, lostbit = 1;

  if (ssize<=0 || dsize<=0) return -1;
  *cdst++=*csrc++;

  while ( 1 ) {
    if ((oob=doubledl(&csrc, &mydl, source, ssize))) {
      if (oob == -1)
	return -1;
      /* 164 */
      backsize = 0;
      if ((oob=doubledl(&csrc, &mydl, source, ssize))) {
	if (oob == -1)
	  return -1;
	/* 16a */
	backbytes = 0;
	if ((oob=doubledl(&csrc, &mydl, source, ssize))) {
	  if (oob == -1)
	    return -1;
	  /* 170 */
	  lostbit = 1;
	  backsize++;
	  backbytes = 0x10;
	  while ( backbytes < 0x100 ) {
	    if ((oob=doubledl(&csrc, &mydl, source, ssize)) == -1)
	      return -1;
	    backbytes = backbytes*2+oob;
	  }
	  backbytes &= 0xff;
	  if ( ! backbytes ) {
	    if (cdst >= dest+dsize)
	      return -1;
	    *cdst++=0x00;
	    continue;
	  }
	} else {
	  /* 18f */
	  if (csrc >= source+ssize)
	    return -1;
	  backbytes = *(unsigned char*)csrc;
	  backsize = backsize * 2 + (backbytes & 1);
	  backbytes = (backbytes & 0xff)>>1;
	  csrc++;
	  if (! backbytes)
	    break;
	  backsize+=2;
	  oldback = backbytes;
	  lostbit = 0;
	}
      } else {
	/* 180 */
	backsize = 1;
	do {
	  if ((oob=doubledl(&csrc, &mydl, source, ssize)) == -1)
	    return -1;
	  backsize = backsize*2+oob;
	  if ((oob=doubledl(&csrc, &mydl, source, ssize)) == -1)
	    return -1;
	} while (oob);

	backsize = backsize - 1 - lostbit;
	if (! backsize) {
	  /* 18a */
	  backsize = 1;
	  do {
	    if ((oob=doubledl(&csrc, &mydl, source, ssize)) == -1)
	      return -1;
	    backsize = backsize*2+oob;
	    if ((oob=doubledl(&csrc, &mydl, source, ssize)) == -1)
	      return -1;
	  } while (oob);

	  backbytes = oldback;
	} else {
	  /* 198 */
	  if (csrc >= source+ssize)
	    return -1;
	  backbytes = *(unsigned char*)csrc;
	  backbytes += (backsize-1)<<8;
	  backsize = 1;
	  csrc++;
	  do {
	    if ((oob=doubledl(&csrc, &mydl, source, ssize)) == -1)
	      return -1;
	    backsize = backsize*2+oob;
	    if ((oob=doubledl(&csrc, &mydl, source, ssize)) == -1)
	      return -1;
	  } while (oob);

          if (backbytes >= 0x7d00)
            backsize++;
          if (backbytes >= 0x500)
            backsize++;
          if (backbytes <= 0x7f)
            backsize += 2;

	  oldback = backbytes;
	}
	lostbit = 0;
      }
      if (!CLI_ISCONTAINED(dest, dsize, cdst, backsize) || !CLI_ISCONTAINED(dest, dsize, cdst-backbytes, backsize))
	return -1;
      while(backsize--) {
	*cdst=*(cdst-backbytes);
	cdst++;
      }

    } else {
      /* 15d */
      if (cdst < dest || cdst >= dest+dsize || csrc < source || csrc >= source+ssize)
	return -1;
      *cdst++=*csrc++;
      lostbit=1;
    }
  }

  if (endsrc) *endsrc = csrc;
  if (enddst) *enddst = cdst;
  return 0;
}

int unfsg_200(char *source, char *dest, int ssize, int dsize, uint32 rva, uint32 base, uint32 ep, int file) {
  struct exe_section section; /* Yup, just one ;) */
  
  if ( cli_unfsg(source, dest, ssize, dsize, NULL, NULL) ) return -1;
  
  section.raw=0;
  section.rsz = dsize;
  section.vsz = dsize;
  section.rva = rva;

  if (!cli_rebuildpe(dest, &section, 1, base, ep, 0, 0, file)) {
    cli_dbgmsg("FSG: Rebuilding failed\n");
    return 0;
  }
  return 1;
}
