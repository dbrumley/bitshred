#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bfd.h>
#include <dis-asm.h>
#include <stdint.h>

typedef struct section {
    char *name;
    bfd_byte *data;
    bfd_size_type datasize;
    bfd_vma vma;
    asection *section;
    int is_code;
    struct section *next;
} section_t;

typedef struct bincode {
    char *filename;
    bfd *abfd;
    bfd_size_type filesize;
    bfd_vma start_addr;
    struct disassemble_info disasm_info;
    struct section *sec;
} bincode_t;

/* bincode.c */
void free_bincode(bincode_t *bin);
bincode_t *initialize_bincode(const char *file);
