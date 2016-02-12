#ifndef __PE_H
#define __PE_H

#include <stdlib.h>
#include "bs_types.h"

/** Header for this PE file */
struct pe_image_file_hdr {
    uint32 Magic;  /**< PE magic header: PE\\0\\0 */
    uint16 Machine;/**< CPU this executable runs on, see libclamav/pe.c for possible values */
    uint16 NumberOfSections;/**< Number of sections in this executable */
    uint32 TimeDateStamp;   /**< Unreliable */
    uint32 PointerToSymbolTable;	    /**< debug */
    uint32 NumberOfSymbols;		    /**< debug */
    uint16 SizeOfOptionalHeader;	    /**< == 224 */
    uint16 Characteristics;
};

/** PE data directory header */
struct pe_image_data_dir {
    uint32 VirtualAddress;
    uint32 Size;
};

/** 32-bit PE optional header */
struct pe_image_optional_hdr32 {
    uint16 Magic;
    uint8  MajorLinkerVersion;		    /**< unreliable */
    uint8  MinorLinkerVersion;		    /**< unreliable */
    uint32 SizeOfCode;			    /**< unreliable */
    uint32 SizeOfInitializedData;		    /**< unreliable */
    uint32 SizeOfUninitializedData;		    /**< unreliable */
    uint32 AddressOfEntryPoint;
    uint32 BaseOfCode;
    uint32 BaseOfData;
    uint32 ImageBase;				    /**< multiple of 64 KB */
    uint32 SectionAlignment;			    /**< usually 32 or 4096 */
    uint32 FileAlignment;			    /**< usually 32 or 512 */
    uint16 MajorOperatingSystemVersion;	    /**< not used */
    uint16 MinorOperatingSystemVersion;	    /**< not used */
    uint16 MajorImageVersion;			    /**< unreliable */
    uint16 MinorImageVersion;			    /**< unreliable */
    uint16 MajorSubsystemVersion;
    uint16 MinorSubsystemVersion;
    uint32 Win32VersionValue;			    /* < ? */
    uint32 SizeOfImage;
    uint32 SizeOfHeaders;
    uint32 CheckSum;				    /**< NT drivers only */
    uint16 Subsystem;
    uint16 DllCharacteristics;
    uint32 SizeOfStackReserve;
    uint32 SizeOfStackCommit;
    uint32 SizeOfHeapReserve;
    uint32 SizeOfHeapCommit;
    uint32 LoaderFlags;			    /* < ? */
    uint32 NumberOfRvaAndSizes;		    /**< unreliable */
    struct pe_image_data_dir DataDirectory[16];
};

/** PE 64-bit optional header */
struct pe_image_optional_hdr64 {
    uint16 Magic;
    uint8  MajorLinkerVersion;		    /**< unreliable */
    uint8  MinorLinkerVersion;		    /**< unreliable */
    uint32 SizeOfCode;			    /**< unreliable */
    uint32 SizeOfInitializedData;		    /**< unreliable */
    uint32 SizeOfUninitializedData;		    /**< unreliable */
    uint32 AddressOfEntryPoint;
    uint32 BaseOfCode;
    uint64 ImageBase;				    /**< multiple of 64 KB */
    uint32 SectionAlignment;			    /**< usually 32 or 4096 */
    uint32 FileAlignment;			    /**< usually 32 or 512 */
    uint16 MajorOperatingSystemVersion;	    /**< not used */
    uint16 MinorOperatingSystemVersion;	    /**< not used */
    uint16 MajorImageVersion;			    /**< unreliable */
    uint16 MinorImageVersion;			    /**< unreliable */
    uint16 MajorSubsystemVersion;
    uint16 MinorSubsystemVersion;
    uint32 Win32VersionValue;			    /* ? */
    uint32 SizeOfImage;
    uint32 SizeOfHeaders;
    uint32 CheckSum;				    /**< NT drivers only */
    uint16 Subsystem;
    uint16 DllCharacteristics;
    uint64 SizeOfStackReserve;
    uint64 SizeOfStackCommit;
    uint64 SizeOfHeapReserve;
    uint64 SizeOfHeapCommit;
    uint32 LoaderFlags;			    /* ? */
    uint32 NumberOfRvaAndSizes;		    /**< unreliable */
    struct pe_image_data_dir DataDirectory[16];
};

/** PE section header */
struct pe_image_section_hdr {
  uint8 Name[8];			    /**< may not end with NULL */
  uint32 VirtualSize;
  uint32 VirtualAddress;
  uint32 SizeOfRawData;		    /**< multiple of FileAlignment */
  uint32 PointerToRawData;		    /**< offset to the section's data */
  uint32 PointerToRelocations;	    /**< object files only */
  uint32 PointerToLinenumbers;	    /**< object files only */
  uint16 NumberOfRelocations;	    /**< object files only */
  uint16 NumberOfLinenumbers;	    /**< object files only */
  uint32 Characteristics;
};


struct exe_section {
  uint32 rva;/**< Relative VirtualAddress */
  uint32 vsz;/**< VirtualSize */
  uint32 raw;/**< Raw offset (in file) */
  uint32 rsz;/**< Raw size (in file) */
  uint32 chr;/**< Section characteristics */
  uint32 urva; /**< PE - unaligned VirtualAddress */
  uint32 uvsz; /**< PE - unaligned VirtualSize */
  uint32 uraw; /**< PE - unaligned PointerToRawData */
  uint32 ursz; /**< PE - unaligned SizeOfRawData */
  char *data;
};

struct exe_info {
  struct exe_section *section;
  uint32 offset;
  uint32 ep;
  uint32 vep;
  uint16 nsections;
  uint32 hdr_size;
  uint32 falign;
  uint32 valign;
  uint32 baseaddr;
};


int cli_peheader(char *map, size_t len, struct exe_info *peinfo);
uint32 cli_rawaddr(uint32 rva, const struct exe_section *shp, uint16 nos, unsigned int *err, size_t fsize, uint32 hdr_size);
int fmap_readn(char *m, void *dst, size_t at, size_t len);

#endif
