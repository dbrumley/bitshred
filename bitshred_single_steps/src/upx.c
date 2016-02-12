#include "fromclamav.h"
#include "bs_types.h"
#include "pe.h"
#include "upx.h"
#include <stdlib.h>
#include <string.h>
/* #include <stdlib.h> */

/* #include "str.h" */
#include "lzma_iface.h"

#define HEADERS "\
\x4D\x5A\x90\x00\x02\x00\x00\x00\x04\x00\x0F\x00\xFF\xFF\x00\x00\
\xB0\x00\x00\x00\x00\x00\x00\x00\x40\x00\x1A\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xD0\x00\x00\x00\
\x0E\x1F\xB4\x09\xBA\x0D\x00\xCD\x21\xB4\x4C\xCD\x21\x54\x68\x69\
\x73\x20\x66\x69\x6C\x65\x20\x77\x61\x73\x20\x63\x72\x65\x61\x74\
\x65\x64\x20\x62\x79\x20\x43\x6C\x61\x6D\x41\x56\x20\x66\x6F\x72\
\x20\x69\x6E\x74\x65\x72\x6E\x61\x6C\x20\x75\x73\x65\x20\x61\x6E\
\x64\x20\x73\x68\x6F\x75\x6C\x64\x20\x6E\x6F\x74\x20\x62\x65\x20\
\x72\x75\x6E\x2E\x0D\x0A\x43\x6C\x61\x6D\x41\x56\x20\x2D\x20\x41\
\x20\x47\x50\x4C\x20\x76\x69\x72\x75\x73\x20\x73\x63\x61\x6E\x6E\
\x65\x72\x20\x2D\x20\x68\x74\x74\x70\x3A\x2F\x2F\x77\x77\x77\x2E\
\x63\x6C\x61\x6D\x61\x76\x2E\x6E\x65\x74\x0D\x0A\x24\x00\x00\x00\
"

#define FAKEPE "\
\x50\x45\x00\x00\x4C\x01\x01\x00\x43\x4C\x41\x4D\x00\x00\x00\x00\
\x00\x00\x00\x00\xE0\x00\x83\x8F\x0B\x01\x00\x00\x00\x10\x00\x00\
\x00\x10\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x10\x00\x00\
\x00\x10\x00\x00\x00\x00\x40\x00\x00\x10\x00\x00\x00\x02\x00\x00\
\x01\x00\x00\x00\x00\x00\x00\x00\x03\x00\x0A\x00\x00\x00\x00\x00\
\xFF\xFF\xFF\xFF\x00\x02\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\
\x00\x00\x10\x00\x00\x10\x00\x00\x00\x00\x10\x00\x00\x10\x00\x00\
\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x2e\x63\x6c\x61\x6d\x30\x31\x00\
\xFF\xFF\xFF\xFF\x00\x10\x00\x00\xFF\xFF\xFF\xFF\x00\x02\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\
"

static char *checkpe(char *dst, uint32 dsize, char *pehdr, uint32 *valign, unsigned int *sectcnt)
{
  char *sections;
  if (!CLI_ISCONTAINED(dst, dsize,  pehdr, 0xf8)) return NULL;

  if (cli_readint32(pehdr) != 0x4550 ) return NULL;
  
  if (!(*valign=cli_readint32(pehdr+0x38))) return NULL;
  
  sections = pehdr+0xf8;
  if (!(*sectcnt = (unsigned char)pehdr[6] + (unsigned char)pehdr[7]*256)) return NULL;
  
  if (!CLI_ISCONTAINED(dst, dsize, sections, *sectcnt*0x28)) return NULL;

  return sections;
}



/* PE from UPX */

static int pefromupx (char *src, uint32 ssize, char *dst, uint32 *dsize, uint32 ep, uint32 upx0, uint32 upx1, uint32 *magic, uint32 dend)
{
  char *imports, *sections=NULL, *pehdr=NULL, *newbuf;
  unsigned int sectcnt=0, upd=1;
  uint32 realstuffsz=0, valign=0;
  uint32 foffset=0xd0+0xf8;

  cli_dbgmsg("UPX: pefromupx");

  if((dst == NULL) || (src == NULL))
    return 0;

  while ((valign=magic[sectcnt++])) {
    if ( ep - upx1 + valign <= ssize-5  &&    /* Wondering how we got so far?! */
	 src[ep - upx1 + valign - 2] == '\x8d' && /* lea edi, ...                  */
	 src[ep - upx1 + valign - 1] == '\xbe' )  /* ... [esi + offset]          */
      break;
  }

  if (!valign && ep - upx1 + 0x80 < ssize-8) {
    const char *pt = &src[ep - upx1 + 0x80];
    cli_dbgmsg("UPX: bad magic - scanning for imports\n");
    
    while ((pt=cli_memstr(pt, ssize - (pt-src) - 8, "\x8d\xbe", 2))) {
      if (pt[6] == '\x8b' && pt[7] == '\x07') { /* lea edi, [esi+imports] / mov eax, [edi] */
	valign=pt-src+2-ep+upx1;
	break;
      }
      pt++;
    }
  }

  if (valign && CLI_ISCONTAINED(src, ssize, src + ep - upx1 + valign, 4)) {
    imports = dst + cli_readint32(src + ep - upx1 + valign);
    
    realstuffsz = imports-dst;
    
    if (realstuffsz >= *dsize ) {
      cli_dbgmsg("UPX: wrong realstuff size\n");
      /* fallback and eventually craft */
    } else {
      pehdr = imports;
      while (CLI_ISCONTAINED(dst, *dsize,  pehdr, 8) && cli_readint32(pehdr)) {
	pehdr+=8;
	while(CLI_ISCONTAINED(dst, *dsize,  pehdr, 2) && *pehdr) {
	  pehdr++;
	  while (CLI_ISCONTAINED(dst, *dsize,  pehdr, 2) && *pehdr)
	    pehdr++;
	  pehdr++;
	}
	pehdr++;
      }
      
      pehdr+=4;
      if (!(sections=checkpe(dst, *dsize, pehdr, &valign, &sectcnt))) pehdr=NULL;
    }
  }

  if (!pehdr && dend>0xf8+0x28) {
    cli_dbgmsg("UPX: no luck - scanning for PE\n");
    return -1; /* !!! */
    /* pehdr = &dst[dend-0xf8-0x28]; */
    /* while (pehdr>dst) { */
    /*   if ((sections=checkpe(dst, *dsize, pehdr, &valign, &sectcnt))) */
    /* 	break; */
    /*   pehdr--; */
    /* } */
    if (!(realstuffsz = pehdr-dst)) pehdr=NULL;
  }

  if (!pehdr) {
    uint32 rebsz = PESALIGN(dend, 0x1000);
    cli_dbgmsg("UPX: no luck - brutally crafing a reasonable PE\n");
    if (!(newbuf = (char *)calloc(rebsz+0x200, sizeof(char)))) {
      cli_dbgmsg("UPX: malloc failed - giving up rebuild\n");
      return 0;
    }
    memcpy(newbuf, HEADERS, 0xd0);
    memcpy(newbuf+0xd0, FAKEPE, 0x120);
    memcpy(newbuf+0x200, dst, dend);
    memcpy(dst, newbuf, dend+0x200);
    free(newbuf);
    cli_writeint32(dst+0xd0+0x50, rebsz+0x1000);
    cli_writeint32(dst+0xd0+0x100, rebsz);
    cli_writeint32(dst+0xd0+0x108, rebsz);
    *dsize=rebsz+0x200;
    cli_dbgmsg("UPX: PE structure added to uncompressed data\n");
    return 1;
  }
  
  foffset = PESALIGN(foffset+0x28*sectcnt, valign);
  
  for (upd = 0; upd <sectcnt ; upd++) {
    uint32 vsize=PESALIGN((uint32)cli_readint32(sections+8), valign);
    uint32 urva=PEALIGN((uint32)cli_readint32(sections+12), valign);
    
    /* Within bounds ? */
    if (!CLI_ISCONTAINED(upx0, realstuffsz, urva, vsize)) {
      cli_dbgmsg("UPX: Sectout of bounds - giving up rebuild\n");
      return 0;
    }
    
    cli_writeint32(sections+8, vsize);
    cli_writeint32(sections+12, urva);
    cli_writeint32(sections+16, vsize);
    cli_writeint32(sections+20, foffset);
    foffset+=vsize;
    
    sections+=0x28;
  }

  cli_writeint32(pehdr+8, 0x4d414c43);
  cli_writeint32(pehdr+0x3c, valign);

  if (!(newbuf = (char *) calloc(foffset, sizeof(char)))) {
    cli_dbgmsg("UPX: malloc failed - giving up rebuild\n");
    return 0;
  }
  
  memcpy(newbuf, HEADERS, 0xd0);
  memcpy(newbuf+0xd0, pehdr,0xf8+0x28*sectcnt);
  sections = pehdr+0xf8;
  for (upd = 0; upd <sectcnt ; upd++) {
    memcpy(newbuf+cli_readint32(sections+20), dst+cli_readint32(sections+12)-upx0, cli_readint32(sections+16));
    sections+=0x28;
  }

  /* CBA restoring the imports they'll look different from the originals anyway... */
  /* ...and yeap i miss the icon too :P */

  if (foffset > *dsize + 8192) {
    cli_dbgmsg("UPX: wrong raw size - giving up rebuild\n");
    free(newbuf);
    return 0;
  }
  memcpy(dst, newbuf, foffset);
  *dsize = foffset;
  free(newbuf);

  cli_dbgmsg("UPX: PE structure rebuilt from compressed file\n");
  return 1;
}


/* [doubleebx] */

static int doubleebx(char *src, uint32 *myebx, uint32 *scur, uint32 ssize)
{
  uint32 oldebx = *myebx;

  *myebx*=2;
  if ( !(oldebx & 0x7fffffff)) {
    if (! CLI_ISCONTAINED(src, ssize, src+*scur, 4))
      {
	cli_dbgmsg("UPX : doubleebx fails");
	return -1;
      }
    oldebx = cli_readint32(src+*scur);
    *myebx = oldebx*2+1;
    *scur+=4;
  }
  return (oldebx>>31);
}

/* [inflate] */

int upx_inflate2b(char *src, uint32 ssize, char *dst, uint32 *dsize, uint32 upx0, uint32 upx1, uint32 ep)
{
  int32_t backbytes, unp_offset = -1;
  uint32 backsize, myebx = 0, scur=0, dcur=0, i, magic[]={0x108,0x110,0xd5,0};
  int oob;
  
  while (1) {
    while ((oob = doubleebx(src, &myebx, &scur, ssize)) == 1) {
      if (scur>=ssize || dcur>=*dsize)
	return -1;
      dst[dcur++] = src[scur++];
    }

    if ( oob == -1 )
      return -1;
    
    backbytes = 1;

    while (1) {
      if ( (oob = doubleebx(src, &myebx, &scur, ssize)) == -1 )
        return -1;
      backbytes = backbytes*2+oob;
      if ( (oob = doubleebx(src, &myebx, &scur, ssize)) == -1 )
	return -1;
      if (oob)
        break;
    }

    backbytes-=3;
  
    if ( backbytes >= 0 ) {

      if (scur>=ssize)
	return -1;
      backbytes<<=8;
      backbytes+=(unsigned char)(src[scur++]);
      backbytes^=0xffffffff;

      if (!backbytes)
	break;
      unp_offset = backbytes;
    }

    if ( (backsize = (uint32)doubleebx(src, &myebx, &scur, ssize)) == 0xffffffff)
      return -1;
    if ( (oob = doubleebx(src, &myebx, &scur, ssize)) == -1)
      return -1;
    backsize = backsize*2 + oob;
    if (!backsize) {
      backsize++;
      do {
        if ( (oob = doubleebx(src, &myebx, &scur, ssize)) == -1)
          return -1;
	backsize = backsize*2 + oob;
      } while ((oob = doubleebx(src, &myebx, &scur, ssize)) == 0);
      if ( oob == -1 )
        return -1;
      backsize+=2;
    }

    if ( (uint32)unp_offset < 0xfffff300 )
      backsize++;

    backsize++;

    if (!CLI_ISCONTAINED(dst, *dsize, dst+dcur+unp_offset, backsize) || !CLI_ISCONTAINED(dst, *dsize, dst+dcur, backsize) || unp_offset >=0)
      return -1;
    for (i = 0; i < backsize; i++)
      dst[dcur + i] = dst[dcur + unp_offset + i];
    dcur+=backsize;
  }

  return pefromupx (src, ssize, dst, dsize, ep, upx0, upx1, magic, dcur);
}

int upx_inflate2d(char *src, uint32 ssize, char *dst, uint32 *dsize, uint32 upx0, uint32 upx1, uint32 ep)
{
  int32_t backbytes, unp_offset = -1;
  uint32 backsize, myebx = 0, scur=0, dcur=0, i, magic[]={0x11c,0x124,0};
  int oob;

  while (1) {
    while ( (oob = doubleebx(src, &myebx, &scur, ssize)) == 1) {
      if (scur>=ssize || dcur>=*dsize)
	return -1;
      dst[dcur++] = src[scur++];
    }

    if ( oob == -1 )
      return -1;

    backbytes = 1;

    while (1) {
      if ( (oob = doubleebx(src, &myebx, &scur, ssize)) == -1 )
        return -1;
      backbytes = backbytes*2+oob;
      if ( (oob = doubleebx(src, &myebx, &scur, ssize)) == -1 )
        return -1;
      if (oob)
	break;
      backbytes--;
      if ( (oob = doubleebx(src, &myebx, &scur, ssize)) == -1 )
        return -1;
      backbytes=backbytes*2+oob;
    }

    backsize = 0;
    backbytes-=3;
  
    if ( backbytes >= 0 ) {

      if (scur>=ssize)
	return -1;
      backbytes<<=8;
      backbytes+=(unsigned char)(src[scur++]);
      backbytes^=0xffffffff;

      if (!backbytes)
	break;
      backsize = backbytes & 1;
      CLI_SAR(backbytes,1);
      unp_offset = backbytes;
    } else {
      if ( (backsize = (uint32)doubleebx(src, &myebx, &scur, ssize)) == 0xffffffff )
        return -1;
    }
 
    if ( (oob = doubleebx(src, &myebx, &scur, ssize)) == -1 )
      return -1;
    backsize = backsize*2 + oob;
    if (!backsize) {
      backsize++;
      do {
        if ( (oob = doubleebx(src, &myebx, &scur, ssize)) == -1 )
          return -1;
	backsize = backsize*2 + oob;
      } while ( (oob = doubleebx(src, &myebx, &scur, ssize)) == 0);
      if ( oob == -1 )
        return -1;
      backsize+=2;
    }

    if ( (uint32)unp_offset < 0xfffffb00 )
      backsize++;

    backsize++;
    if (!CLI_ISCONTAINED(dst, *dsize, dst+dcur+unp_offset, backsize) || !CLI_ISCONTAINED(dst, *dsize, dst+dcur, backsize) || unp_offset >=0 )
      return -1;
    for (i = 0; i < backsize; i++)
      dst[dcur + i] = dst[dcur + unp_offset + i];
    dcur+=backsize;
  }

  return pefromupx (src, ssize, dst, dsize, ep, upx0, upx1, magic, dcur);
}

int upx_inflate2e(char *src, uint32 ssize, char *dst, uint32 *dsize, uint32 upx0, uint32 upx1, uint32 ep)
{
  int32 backbytes, unp_offset = -1;
  uint32 backsize, myebx = 0, scur=0, dcur=0, i, magic[]={0x128,0x130,0};
  int oob;


  printf("inflate2e: ssize = %x, dsize = %x, vep = %x, rva0 = %x, rva1 = %x\n", ssize, *dsize, ep,upx0, upx1);

  for(;;) {
    while ( (oob = doubleebx(src, &myebx, &scur, ssize)) ) {
      if (oob == -1)
        return -1;
      if (scur>=ssize || dcur>=*dsize)
	return -1;
      dst[dcur++] = src[scur++];
    }

    backbytes = 1;

    for(;;) {
      if ( (oob = doubleebx(src, &myebx, &scur, ssize)) == -1 )
        return -1;
      backbytes = backbytes*2+oob;
      if ( (oob = doubleebx(src, &myebx, &scur, ssize)) == -1 )
        return -1;
      if ( oob )
	break;
      backbytes--;
      if ( (oob = doubleebx(src, &myebx, &scur, ssize)) == -1 )
        return -1;
      backbytes=backbytes*2+oob;
    }

    backbytes-=3;
  
    if ( backbytes >= 0 ) {

      if (scur>=ssize) {
	cli_dbgmsg("UPX: scur>=ssize");
	return -1;
      }
      backbytes<<=8;
      backbytes+=(unsigned char)(src[scur++]);
      backbytes^=0xffffffff;

      if (!backbytes)
	break;
      backsize = backbytes & 1; /* Using backsize to carry on the shifted out bit (UPX uses CF) */
      CLI_SAR(backbytes,1);
      unp_offset = backbytes;
    } else {
      if ( (backsize = (uint32)doubleebx(src, &myebx, &scur, ssize)) == 0xffffffff )
        return -1;
    } /* Using backsize to carry on the doubleebx result (UPX uses CF) */

    if (backsize) { /* i.e. IF ( last sar shifted out 1 bit || last doubleebx()==1 ) */
      if ( (backsize = (uint32)doubleebx(src, &myebx, &scur, ssize)) == 0xffffffff )
        return -1;
    } else {
      backsize = 1;
      if ((oob = doubleebx(src, &myebx, &scur, ssize)) == -1)
        return -1;
      if (oob) {
	if ((oob = doubleebx(src, &myebx, &scur, ssize)) == -1)
	  return -1;
	  backsize = 2 + oob;
	} else {
	  do {
	    if ((oob = doubleebx(src, &myebx, &scur, ssize)) == -1)
	      return -1;
	    backsize = backsize * 2 + oob;
	  } while ((oob = doubleebx(src, &myebx, &scur, ssize)) == 0);
	  if (oob == -1)
	    return -1;
	  backsize+=2;
	}
    }
 
    if ( (uint32)unp_offset < 0xfffffb00 ) 
      backsize++;

    backsize+=2;

    /* printf("dsize = %x, dcur = %x, unp_offset = %x, backsize = %x\n", *dsize, dcur, unp_offset, backsize); */

    if (!CLI_ISCONTAINED(dst, *dsize, dst+dcur+unp_offset, backsize)) {
      cli_dbgmsg("UPX: !CLI_ISCON..1");
      return -1;
    }

    if (!CLI_ISCONTAINED(dst, *dsize, dst+dcur, backsize)) {
      cli_dbgmsg("UPX: !CLI_ISCON..2");
      return -1;
    }

    if (unp_offset >=0 ){
      cli_dbgmsg("UPX: !CLI_ISCON..3");
      return -1;
    }
    for (i = 0; i < backsize; i++)
      dst[dcur + i] = dst[dcur + unp_offset + i];
    dcur+=backsize;
  }

  return pefromupx (src, ssize, dst, dsize, ep, upx0, upx1, magic, dcur);
}

int upx_inflatelzma(char *src, uint32 ssize, char *dst, uint32 *dsize, uint32 upx0, uint32 upx1, uint32 ep) {
  struct CLI_LZMA l;
  uint32 magic[]={0xb16,0xb1e,0};
  unsigned char fake_lzmahdr[5];

  memset(&l, 0, sizeof(l));
  cli_writeint32(fake_lzmahdr + 1, *dsize);
  *fake_lzmahdr = 3 /* lc */ + 9* ( 5* 2 /* pb */ + 0 /* lp */);
  l.next_in = fake_lzmahdr;
  l.avail_in = 5;
  if(cli_LzmaInit(&l, *dsize) != LZMA_RESULT_OK)
      return 0;
  l.avail_in = ssize;
  l.avail_out = *dsize;
  l.next_in = (unsigned char*)src+2;
  l.next_out = (unsigned char*)dst;

  if(cli_LzmaDecode(&l)==LZMA_RESULT_DATA_ERROR) {
/*     __asm__ __volatile__("int3"); */
    cli_LzmaShutdown(&l);
    return -1;
  }
  cli_LzmaShutdown(&l);

  return pefromupx (src, ssize, dst, dsize, ep, upx0, upx1, magic, *dsize);
}
