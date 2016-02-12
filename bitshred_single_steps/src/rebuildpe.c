#include <string.h>

#include "fromclamav.h"
#include "rebuildpe.h"

struct IMAGE_PE_HEADER {
    uint32 Signature;
    /* FILE HEADER */
    uint16    Machine;
    uint16    NumberOfSections;
    uint32   TimeDateStamp;
    uint32   PointerToSymbolTable;
    uint32   NumberOfSymbols;
    uint16    SizeOfOptionalHeader;
    uint16    Characteristics;
    /* OPTIONAL HEADER */
    uint16    Magic;
    uint8    MajorLinkerVersion;
    uint8   MinorLinkerVersion;
    uint32   SizeOfCode;
    uint32   SizeOfInitializedData;
    uint32   SizeOfUninitializedData;
    uint32   AddressOfEntryPoint;
    uint32   BaseOfCode;
    uint32   BaseOfData;
    /* NT additional fields. */
    uint32   ImageBase;
    uint32   SectionAlignment;
    uint32   FileAlignment;
    uint16    MajorOperatingSystemVersion;
    uint16    MinorOperatingSystemVersion;
    uint16    MajorImageVersion;
    uint16    MinorImageVersion;
    uint16    MajorSubsystemVersion;
    uint16    MinorSubsystemVersion;
    uint32   Win32VersionValue;
    uint32   SizeOfImage;
    uint32   SizeOfHeaders;
    uint32   CheckSum;
    uint16    Subsystem;
    uint16    DllCharacteristics;
    uint32   SizeOfStackReserve;
    uint32   SizeOfStackCommit;
    uint32   SizeOfHeapReserve;
    uint32   SizeOfHeapCommit;
    uint32   LoaderFlags;
    uint32   NumberOfRvaAndSizes;
    /* IMAGE_DATA_DIRECTORY follows.... */
};

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
\x50\x45\x00\x00\x4C\x01\xFF\xFF\x43\x4C\x41\x4D\x00\x00\x00\x00\
\x00\x00\x00\x00\xE0\x00\x83\x8F\x0B\x01\x00\x00\x00\x10\x00\x00\
\x00\x10\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFF\x00\x10\x00\x00\
\x00\x10\x00\x00\xFF\xFF\xFF\xFF\x00\x10\x00\x00\x00\x02\x00\x00\
\x01\x00\x00\x00\x00\x00\x00\x00\x03\x00\x0A\x00\x00\x00\x00\x00\
\x00\x10\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\
\x00\x00\x10\x00\x00\x10\x00\x00\x00\x00\x10\x00\x00\x10\x00\x00\
\x00\x00\x00\x00\x10\x00\x00\x00\
"

int cli_rebuildpe(char *buffer, struct exe_section *sections, int sects, uint32 base, uint32 ep, uint32 ResRva, uint32 ResSize, int file)
{
  uint32 datasize=0, rawbase=PESALIGN(0x148+0x80+0x28*sects, 0x200);
  char *pefile=NULL, *curpe;
  struct IMAGE_PE_HEADER *fakepe;
  int i, gotghost=(sections[0].rva > PESALIGN(rawbase, 0x1000));

  if (gotghost) rawbase=PESALIGN(0x148+0x80+0x28*(sects+1), 0x200);

  if(sects+gotghost > 96)
    return 0;

  for (i=0; i < sects; i++)
    datasize+=PESALIGN(sections[i].rsz, 0x200);

  if(datasize > CLI_MAX_ALLOCATION)
    return 0;

  if((pefile = (char *) calloc(rawbase+datasize, 1))) {
    memcpy(pefile, HEADERS, 0x148);

    datasize = PESALIGN(rawbase, 0x1000);

    fakepe = (struct IMAGE_PE_HEADER *)(pefile+0xd0);
    fakepe->NumberOfSections = EC16(sects+gotghost);
    fakepe->AddressOfEntryPoint = EC32(ep);
    fakepe->ImageBase = EC32(base);
    fakepe->SizeOfHeaders = EC32(rawbase);
    memset(pefile+0x148, 0, 0x80);
    cli_writeint32(pefile+0x148+0x10, ResRva);
    cli_writeint32(pefile+0x148+0x14, ResSize);
    curpe = pefile+0x148+0x80;

    if (gotghost) {
      snprintf(curpe, 8, "empty");
      cli_writeint32(curpe+8, sections[0].rva-datasize); /* vsize */
      cli_writeint32(curpe+12, datasize); /* rva */
      cli_writeint32(curpe+0x24, 0xffffffff);
      curpe+=40;
      datasize+=PESALIGN(sections[0].rva-datasize, 0x1000);
    }

    for (i=0; i < sects; i++) {
      snprintf(curpe, 8, ".clam%.2d", i+1);
      cli_writeint32(curpe+8, sections[i].vsz);
      cli_writeint32(curpe+12, sections[i].rva);
      cli_writeint32(curpe+16, sections[i].rsz);
      cli_writeint32(curpe+20, rawbase);
      /* already zeroed
      cli_writeint32(curpe+24, 0);
      cli_writeint32(curpe+28, 0);
      cli_writeint32(curpe+32, 0);
      */
      cli_writeint32(curpe+0x24, 0xffffffff);
      memcpy(pefile+rawbase, buffer+sections[i].raw, sections[i].rsz);
      rawbase+=PESALIGN(sections[i].rsz, 0x200);
      curpe+=40;
      datasize+=PESALIGN(sections[i].vsz, 0x1000);
    }
    fakepe->SizeOfImage = EC32(datasize);
  } else {
    return 0;
  }

  i = (cli_writen(file, pefile, rawbase)!=-1);
  free(pefile);
  return i;
}
