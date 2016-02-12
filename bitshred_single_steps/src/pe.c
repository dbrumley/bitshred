#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif
#define _XOPEN_SOURCE 500
#include <stdio.h>
#if HAVE_STRING_H
#include <string.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <time.h>
#include <stdarg.h>

#include "fromclamav.h"
#include "bs_types.h"
#include "pe.h"

#define PE_IMAGE_DOS_SIGNATURE	    0x5a4d	    /* MZ */
#define PE_IMAGE_DOS_SIGNATURE_OLD  0x4d5a          /* ZM */
#define PE_IMAGE_NT_SIGNATURE	    0x00004550
#define PE32_SIGNATURE		    0x010b
#define PE32P_SIGNATURE		    0x020b

#define optional_hdr64 pe_opt.opt64
#define optional_hdr32 pe_opt.opt32

int fmap_readn(char *m, void *dst, size_t at, size_t len) {
  char *src;
  src = m + at;
  memcpy(dst, src, len);
  return len;
}

uint32 cli_rawaddr(uint32 rva, const struct exe_section *shp, uint16 nos, unsigned int *err, size_t fsize, uint32 hdr_size)
{
    int i, found = 0;
    uint32 ret;

    if (rva<hdr_size) { /* Out of section EP - mapped to imagebase+rva */
	if (rva >= fsize) {
	    *err=1;
	    return 0;
	}
        *err=0;
	return rva;
    }

    for(i = nos-1; i >= 0; i--) {
        if(shp[i].rsz && shp[i].rva <= rva && shp[i].rsz > rva - shp[i].rva) {
	    found = 1;
	    break;
	}
    }

    if(!found) {
	*err = 1;
	return 0;
    }

    ret = rva - shp[i].rva + shp[i].raw;
    *err = 0;
    return ret;
}

int cli_peheader(char *map, size_t len,  struct exe_info *peinfo)
{
  uint16 e_magic; /* DOS signature ("MZ") */
  uint32 e_lfanew; /* address of new exe header */
  
  struct pe_image_file_hdr file_hdr;
  union {
    struct pe_image_optional_hdr64 opt64;
    struct pe_image_optional_hdr32 opt32;
  } pe_opt;
  struct pe_image_section_hdr *section_hdr;
  int i;
  unsigned int err, pe_plus = 0;
  uint32 valign, falign, hdr_size;
  size_t fsize;
  size_t at;
  struct pe_image_data_dir *dirs;
  
  cli_dbgmsg("in cli_peheader\n");

  fsize = len - peinfo->offset;
  
  if(fmap_readn(map, &e_magic, peinfo->offset, sizeof(e_magic)) != sizeof(e_magic)) {
    cli_dbgmsg("Can't read DOS signature\n");
    return 0; //CL_CLEAN;
  }

  if(EC16(e_magic) != PE_IMAGE_DOS_SIGNATURE && EC16(e_magic) != PE_IMAGE_DOS_SIGNATURE_OLD) {
    cli_dbgmsg("Invalid DOS signature\n");
    return -1;
  }
  
  if(fmap_readn(map, &e_lfanew, peinfo->offset + 58 + sizeof(e_magic), sizeof(e_lfanew)) != sizeof(e_lfanew)) {
    /* truncated header? */
	return -1;
  }
  
  e_lfanew = EC32(e_lfanew);
  if(!e_lfanew) {
    cli_dbgmsg("Not a PE file\n");
    return -1;
  }
  
  if(fmap_readn(map, &file_hdr, peinfo->offset + e_lfanew, sizeof(struct pe_image_file_hdr)) != sizeof(struct pe_image_file_hdr)) {
    /* bad information in e_lfanew - probably not a PE file */
    cli_dbgmsg("Can't read file header\n");
    return -1;
  }
  
  if(EC32(file_hdr.Magic) != PE_IMAGE_NT_SIGNATURE) {
    cli_dbgmsg("Invalid PE signature (probably NE file)\n");
    return -1;
  }
  
  if ( (peinfo->nsections = EC16(file_hdr.NumberOfSections)) < 1 || peinfo->nsections > 96 ) return -1;
  
  if (EC16(file_hdr.SizeOfOptionalHeader) < sizeof(struct pe_image_optional_hdr32)) {
    cli_dbgmsg("SizeOfOptionalHeader too small\n");
    return -1;
  }
  
    at = peinfo->offset + e_lfanew + sizeof(struct pe_image_file_hdr);
    if(fmap_readn(map, &optional_hdr32, at, sizeof(struct pe_image_optional_hdr32)) != sizeof(struct pe_image_optional_hdr32)) {
      cli_dbgmsg("Can't read optional file header\n");
      return -1;
    }
    at += sizeof(struct pe_image_optional_hdr32);
    
    if(EC16(optional_hdr64.Magic)==PE32P_SIGNATURE) { /* PE+ */
      if(EC16(file_hdr.SizeOfOptionalHeader)!=sizeof(struct pe_image_optional_hdr64)) {
	cli_dbgmsg("Incorrect SizeOfOptionalHeader for PE32+\n");
	return -1;
      }
      if(fmap_readn(map, &optional_hdr32 + 1, at, sizeof(struct pe_image_optional_hdr64) - sizeof(struct pe_image_optional_hdr32)) != sizeof(struct pe_image_optional_hdr64) - sizeof(struct pe_image_optional_hdr32)) {
	cli_dbgmsg("Can't read optional file header\n");
	return -1;
      }
      at += sizeof(struct pe_image_optional_hdr64) - sizeof(struct pe_image_optional_hdr32);
      hdr_size = EC32(optional_hdr64.SizeOfHeaders);
      pe_plus=1;
    } else { /* PE */
      if (EC16(file_hdr.SizeOfOptionalHeader)!=sizeof(struct pe_image_optional_hdr32)) {
	/* Seek to the end of the long header */
	at += EC16(file_hdr.SizeOfOptionalHeader)-sizeof(struct pe_image_optional_hdr32);
      }
      hdr_size = EC32(optional_hdr32.SizeOfHeaders);
    }
    
    valign = (pe_plus)?EC32(optional_hdr64.SectionAlignment):EC32(optional_hdr32.SectionAlignment);
    falign = (pe_plus)?EC32(optional_hdr64.FileAlignment):EC32(optional_hdr32.FileAlignment);
    
    peinfo->hdr_size = hdr_size = PESALIGN(hdr_size, valign);
    
    peinfo->section = (struct exe_section *) calloc(peinfo->nsections, sizeof(struct exe_section));
    
    if(!peinfo->section) {
      cli_dbgmsg("Can't allocate memory for section headers\n");
      return -1;
    }
    
    section_hdr = (struct pe_image_section_hdr *) calloc(peinfo->nsections, sizeof(struct pe_image_section_hdr));
    
    if(!section_hdr) {
      cli_dbgmsg("Can't allocate memory for section headers\n");
      free(peinfo->section);
      peinfo->section = NULL;
      return -1;
    }
    
    if(fmap_readn(map, section_hdr, at, peinfo->nsections * sizeof(struct pe_image_section_hdr)) != peinfo->nsections * sizeof(struct pe_image_section_hdr)) {
      cli_dbgmsg("Can't read section header\n");
      cli_dbgmsg("Possibly broken PE file\n");
      free(section_hdr);
      free(peinfo->section);
      peinfo->section = NULL;
      return -1;
    }
    at += sizeof(struct pe_image_section_hdr)*peinfo->nsections;
    
    for(i = 0; falign!=0x200 && i<peinfo->nsections; i++) {
      if (falign && section_hdr[i].SizeOfRawData && EC32(section_hdr[i].PointerToRawData)%falign && !(EC32(section_hdr[i].PointerToRawData)%0x200)) {
	falign = 0x200;
	}
    }
    
    for(i = 0; i < peinfo->nsections; i++) {
      peinfo->section[i].rva = PEALIGN(EC32(section_hdr[i].VirtualAddress), valign);
      peinfo->section[i].vsz = PESALIGN(EC32(section_hdr[i].VirtualSize), valign);
      peinfo->section[i].raw = PEALIGN(EC32(section_hdr[i].PointerToRawData), falign);
      peinfo->section[i].rsz = PESALIGN(EC32(section_hdr[i].SizeOfRawData), falign);
      
      if (!peinfo->section[i].vsz && peinfo->section[i].rsz)
	peinfo->section[i].vsz=PESALIGN(EC32(section_hdr[i].SizeOfRawData), valign);
      
      if (peinfo->section[i].rsz && !CLI_ISCONTAINED(0, (uint32) fsize, peinfo->section[i].raw, peinfo->section[i].rsz))
	peinfo->section[i].rsz = (fsize - peinfo->section[i].raw)*(fsize>peinfo->section[i].raw);
    }
    
    if(pe_plus) {
      peinfo->vep = EC32(optional_hdr64.AddressOfEntryPoint);
      dirs = optional_hdr64.DataDirectory;
    } else {
      peinfo->vep = EC32(optional_hdr32.AddressOfEntryPoint);
      dirs = optional_hdr32.DataDirectory;
    }
    
    if(!(peinfo->ep = cli_rawaddr(peinfo->vep, peinfo->section, peinfo->nsections, &err, fsize, hdr_size)) && err) {
      cli_dbgmsg("Broken PE file\n");
      free(section_hdr);
      free(peinfo->section);
      peinfo->section = NULL;
      return -1;
    }

    peinfo->falign = falign;
    peinfo->valign = valign;
    peinfo->baseaddr = optional_hdr32.ImageBase;
    
    free(section_hdr);
    return 0;
}
