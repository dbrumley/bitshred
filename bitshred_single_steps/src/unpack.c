#include <errno.h>
#include <assert.h>
#include <stdio.h>
#include <fcntl.h>
#include "bincode.h"
#include "bs_common.h"
#include "bs_types.h"
#include "fromclamav.h"
#include "pe.h"
#include "unpack.h"
#include "fsg.h"


int do_unpack(struct exe_info peinfo, char* map, size_t fsize, char *filename) 
{
    unsigned int nsections = 0;
    struct exe_section *exe_sections;
    char epbuff[300];
    unsigned int i;
    uint32 ssize;
    uint32 dsize;
    uint32 vep;
    uint32 ep;
    char *src;
    char *dest;
    int err;
    int ndesc;

    uint32 baseaddr = 0;
    uint32 valign = 0x1000;
    uint32 falign = 0x200;
    int found = 0;
    int success = NOT_PACKED;
    char buf[512];
    char unpacked_filename[512];
    int ret_code = -1;


    bs_dbgmsg("do_unpack.\n");
    nsections = peinfo.nsections;
    exe_sections = peinfo.section;


    for (i=0; i < nsections; i++) {
      bs_dbgmsg("VirtualAddress : %x\n",exe_sections[i].rva);
      bs_dbgmsg("VirtualSize : %x\n",exe_sections[i].vsz);
      bs_dbgmsg("Size : %x\n",exe_sections[i].rsz);
    }


    vep = peinfo.ep;
    ep = cli_rawaddr(vep, exe_sections, nsections, &err, fsize, peinfo.hdr_size);
    fmap_readn(map, epbuff, ep, 300);
    epbuff[299] = '\0';
    bs_dbgmsg("vep = %x\n",vep);
    baseaddr = peinfo.baseaddr;
    valign = peinfo.valign;
    falign = peinfo.falign;
    bs_dbgmsg("baseaddr = %x\n", baseaddr);
    bs_dbgmsg("valign = %x, falign = %x\n",valign, falign);

    found = 0;

    for(i = 0; i < (unsigned int) nsections - 1; i++) {
      if(!exe_sections[i].rsz && exe_sections[i].vsz && exe_sections[i + 1].rsz && exe_sections[i + 1].vsz) {
	found = 1;
	success = PACKED_BUT_FAIL;
	cli_dbgmsg("UPX/FSG/MEW: empty section found - assuming compression\n");
		break;
      }
    }

    /* UPX */

    sprintf(unpacked_filename, "%s.unpacked", filename);
    if (found) {
      unlink(unpacked_filename);
      if(debug_flag)
          sprintf(buf,"upx -d -o%s %s", unpacked_filename, filename);
      else
          sprintf(buf,"upx -qqq -d -o%s %s", unpacked_filename, filename);
      ret_code = system(buf);
    }

    bs_dbgmsg("ret code = %d\n", ret_code);

    if (ret_code == 0) {
      success = UNPACK_SUCCESS;
    }


    if (found && success != UNPACK_SUCCESS) {

      /* FSG 2.0 */
      while(epbuff[0] == '\x87' && epbuff[1] == '\x25') {

	uint32 newesi, newedi, newebx, newedx;
	
	ssize = exe_sections[i + 1].rsz;
	dsize = exe_sections[i].vsz;
	
	if(ssize <= 0x19 || dsize <= ssize) {
	  cli_dbgmsg("FSG: Size mismatch");
	  free(exe_sections);
	  return -1;
	}
	
	newedx = cli_readint32(epbuff + 2) - baseaddr;

	if(!CLI_ISCONTAINED(exe_sections[i + 1].rva, exe_sections[i + 1].rsz, newedx, 4)) {
	  cli_dbgmsg("FSG: xchg out of bounds");
	  break;
	}
	
	if(!exe_sections[i + 1].rsz || !(src = (map + exe_sections[i + 1].raw)  )) {
	  cli_dbgmsg("Can't read raw data of section "); 
	  free(exe_sections);
	  return -1;
	}
	
	dest = src + newedx - exe_sections[i + 1].rva;
	if(newedx < exe_sections[i + 1].rva || !CLI_ISCONTAINED(src, ssize, dest, 4)) {
	  cli_dbgmsg("FSG: New ESP out of bounds\n");
	  break;
	}
	
	newedx = cli_readint32(dest) - baseaddr;

	if(!CLI_ISCONTAINED(exe_sections[i + 1].rva, exe_sections[i + 1].rsz, newedx, 4)) {
	  cli_dbgmsg("FSG: New ESP is wrong\n"); 
	  break;
	}
	
	dest = src + newedx - exe_sections[i + 1].rva;
	if(!CLI_ISCONTAINED(src, ssize, dest, 32)) {
	  cli_dbgmsg("FSG: New stack out of bounds\n");
	  break;
	}
	
	newedi = cli_readint32(dest) - baseaddr; 
	newesi = cli_readint32(dest + 4) - baseaddr;
	newebx = cli_readint32(dest + 16) - baseaddr; 
	newedx = cli_readint32(dest + 20);
	
	if(newedi != exe_sections[i].rva) {
	  cli_dbgmsg("FSG: Bad destination buffer (edi is %x should be ");
	  break;
	}
	
	if(newesi < exe_sections[i + 1].rva || newesi - exe_sections[i + 1].rva >= exe_sections[i + 1].rsz) {
	  cli_dbgmsg("FSG: Source buffer out of section bounds\n");
	  break;
	}
	
	if(!CLI_ISCONTAINED(exe_sections[i + 1].rva, exe_sections[i + 1].rsz, newebx, 16)) {
	  cli_dbgmsg("FSG: Array of functions out of bounds\n");
	  break;
	}
	
	newedx=cli_readint32(newebx + 12 - exe_sections[i + 1].rva + src) - baseaddr; 
	cli_dbgmsg("FSG: found old EP "); 	
	if((dest = (char *) calloc(dsize, sizeof(char))) == NULL) {
	  free(exe_sections);
	  free(src);
	  return -1;
	}
	
	ndesc = open(unpacked_filename,O_WRONLY|O_CREAT, 0644);
	if ( unfsg_200(newesi - exe_sections[i + 1].rva + src, dest, ssize + exe_sections[i + 1].rva - newesi, dsize, newedi, baseaddr, newedx, ndesc) == 1) {
	  success = UNPACK_SUCCESS;
	}

	break;
      }
      
    }
    

    if (success == UNPACK_SUCCESS) {
      bs_dbgmsg("Successfully unpakced\n");
    }

    free(exe_sections);

    return success;
}

int unpack(const char *file)
{
    char *result = NULL;
    unsigned int rsize = 0;
    FILE *fp;
    size_t fsize;
    char *filebuf = NULL;
    struct exe_info peinfo;
    int i;
    int ret_tmp;

    fp = fopen(file,"r");
    fseek(fp, 0, SEEK_END);
    fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    filebuf = calloc(fsize,sizeof(char));
    fread(filebuf, sizeof(char), fsize, fp);
    fclose(fp);

    peinfo.offset = 0;
    if (cli_peheader(filebuf,fsize,&peinfo) == 0) {
      bs_dbgmsg("Successfully parse a PE header\n");
      for (i = 0; i < peinfo.nsections; i++) {
	bs_dbgmsg("Virtual address = %x \n", peinfo.section[i].rva);
	bs_dbgmsg("Virtual size = %x \n", peinfo.section[i].vsz);
	bs_dbgmsg("Pointer to raw data = %x \n", peinfo.section[i].raw);
	bs_dbgmsg("Size of raw data = %x \n", peinfo.section[i].rsz);
      }

    } else {
      bs_dbgmsg("Fail to parse a PE header\n");
    }

    bs_dbgmsg("Try to unpack file : %s\n", file);
    result = NULL;
    rsize = 0;
    ret_tmp = do_unpack(peinfo, filebuf, fsize ,file);
    free(filebuf);
    return ret_tmp;
}
