#include <errno.h>
#include <assert.h>
#include "bincode.h"
#include "bs_common.h"

static int ignore() {
    return 1;
}

int get_instr_length(bincode_t *bin, bfd_vma addr)
{
    disassembler_ftype disas = disassembler(bin->abfd);
    fprintf_ftype old_fprintf_func = bin->disasm_info.fprintf_func;
    bin->disasm_info.fprintf_func = (fprintf_ftype)ignore;
    assert(disas);
    int len = disas(addr, &bin->disasm_info);
    bin->disasm_info.fprintf_func = old_fprintf_func;
    return len;
}

static int my_read_memory (bfd_vma memaddr, bfd_byte *myaddr, unsigned int length, struct disassemble_info *info)
{
    int ret = buffer_read_memory(memaddr,myaddr,length,info);

    if (EIO == ret) {
        bincode_t *bin = info->application_data;
        section_t *sec;
        for(sec=bin->sec;sec!=NULL;sec=sec->next)
            if((memaddr>=sec->vma) && (memaddr<(sec->vma+sec->datasize)))
                break;
        if (NULL == sec)
            return EIO;

        info->buffer = sec->data;
        info->buffer_vma = sec->vma;
        info->buffer_length = sec->datasize;
        info->section = sec->section;

        ret = buffer_read_memory(memaddr,myaddr,length,info);
    }
    return ret;
}

static void init_disasm_info(bfd *abfd, struct disassemble_info *disasm_info)
{
    init_disassemble_info (disasm_info, stdout, (fprintf_ftype) fprintf);
    disasm_info->flavour = bfd_get_flavour (abfd);
    disasm_info->arch = bfd_get_arch (abfd);
    disasm_info->mach = bfd_get_mach (abfd);
    disasm_info->octets_per_byte = bfd_octets_per_byte (abfd);
    disasm_info->disassembler_needs_relocs = FALSE;

    if (bfd_big_endian (abfd))
        disasm_info->display_endian = disasm_info->endian = BFD_ENDIAN_BIG;
    else if (bfd_little_endian (abfd))
        disasm_info->display_endian = disasm_info->endian = BFD_ENDIAN_LITTLE;

    disassemble_init_for_target(disasm_info);
    disasm_info->read_memory_func = my_read_memory;
}

/* initialize section data */
void initialize_section(bincode_t *bin)
{
    asection *section;
    //const char *section_name;
    //flagword section_flags; // unsigned int
    bfd *abfd = bin->abfd;
    section_t *nextsec = NULL;

    for (section=abfd->sections;section!=NULL;section=section->next) {
        section_t *sec;
        bfd_byte *data;
        bfd_size_type datasize = bfd_get_section_size(section);

        if (datasize == 0) continue;

        if((data = malloc(datasize)) == NULL) {
            bs_errmsg("  (!) malloc(): data\n");
            exit(EXIT_FAILURE);
        }
        bfd_get_section_contents(abfd, section, data, 0 ,datasize);
        if((sec = malloc(sizeof(section_t))) == NULL) {
            bs_errmsg("  (!) malloc(): section\n");
            exit(EXIT_FAILURE);
        }
        sec->name = strdup(bfd_section_name(abfd, section));
        sec->data = data;
        sec->datasize = datasize;
        sec->vma = section->vma;
        sec->section = section;
        sec->is_code = section->flags & SEC_CODE;

        sec->next = nextsec;
        nextsec = sec;
    }
    bin->sec = nextsec;
}

/* initialize bincode */
bincode_t *initialize_bincode(const char *file)
{
    bfd *abfd;
    bincode_t *bin;
    //char *target = "x86_64-unknown-linux-gnu";
    char *target = "i686-pc-linux-gnu";

    bfd_init();

    if (!bfd_set_default_target(target)) {
        bs_dbgmsg("  (!) bfd_set_default_target()\n");
        return NULL;
    }

    if ((abfd = bfd_openr(file, target)) == NULL) {
        bs_dbgmsg("  (!) bfd_openr(): %s\n", file);
        return NULL;
    }

    if (!bfd_check_format(abfd, bfd_object)) {
        bs_dbgmsg("  (!) bfd_check_format()\n");
        bfd_close(abfd);
        return NULL;
    }

    if((bin = malloc(sizeof(bincode_t))) == NULL) {
        bs_errmsg("  (!) malloc(): bin\n");
        exit(EXIT_FAILURE);
    }

    bin->filename = strdup(abfd->filename);
    bin->abfd = abfd;
    bin->filesize = bfd_get_size(abfd);
    bin->start_addr = bfd_get_start_address(abfd);
    init_disasm_info(bin->abfd, &bin->disasm_info);
    bin->disasm_info.application_data = bin;
    initialize_section(bin);

    return bin;
}

/* release allocated memory for bincode */
void free_bincode(bincode_t *bin)
{
    free(bin->filename);
    bfd_close(bin->abfd);

    section_t *sec, *prevsec;
    sec = bin->sec;
    while (sec) {
        free(sec->name);
        free(sec->data);
        prevsec = sec;
        sec = sec->next;
        free(prevsec);
    }

    free(bin);
}
