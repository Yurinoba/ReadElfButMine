// Code qui retourne l'adresse de main dans le binaire
#include "readelfbutmine.h"

bool isLittle = true;

char* get_my_file(char* filename){
    int fd = open(filename, O_RDONLY);
    // pas de 3ème paramètre parce qu'on ne veut pas créer d'autre fichier si on se trompe de non
    if(fd == -1){
        printf("t'as mis un mauvais nom boloss\n");
        return NULL;
    }
    struct stat sb;

    if(fstat(fd, &sb) == 1){
        printf("c'est quoi la tailleee, je sais pas... sorry\n");
    }

    char *file_mmap = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    return file_mmap;
}

int main(int argc, char** argv){

    char* beginning = get_my_file(argv[1]);
    if(beginning == NULL){
        return -1;
    }

    Elf64_Off* ph_offset = malloc(sizeof(Elf64_Off));
    Elf64_Half* ph_number = malloc(sizeof(Elf64_Half));
    Elf64_Off* sh_offset = malloc(sizeof(Elf64_Off));
    Elf64_Half* sh_number = malloc(sizeof(Elf64_Half));
    Elf64_Half* sh_shs = malloc(sizeof(Elf64_Half));

    printf("[+] Check du Header ELF : \n\n");

    getInfoHeader(beginning, ph_offset, ph_number, sh_offset, sh_number, sh_shs);

    printf("\n[Info] Fin du check du Header ELF ! \n\n");

    printf("[Info] Check Program Header : \n\n");

    getInfoProgramHeader(beginning + *ph_offset, *ph_number);

    printf("\n[Info] Fin du check Program Header ! \n\n");

    // Program Headers
    //     Les Program Headers disent à l'OS :
    // Quelles parties du fichier doivent être chargées en mémoire
    // Où les mettre en mémoire (adresse virtuelle)
    // Avec quelles permissions (lecture, exécution, etc.)

    printf("[Info] Check Section Header : \n\n");

    getInfoSectionHeader(beginning, *sh_offset, *sh_number, *sh_shs);

    printf("\n[Info] Fin du check Section Header ! \n\n");

    // Sections Headers : pour .text, .data,..

    free(ph_offset);
    free(ph_number);
    free(sh_offset);
    free(sh_number); 
    free(sh_shs);

  return 0;
}

void getInfoHeader(char* beginning_file, Elf64_Off* ph_off, Elf64_Half* ph_num, Elf64_Off* sh_off, Elf64_Half* sh_num, Elf64_Half* sh_shs){



//   Print all the header informations 
//     typedef struct
// {
//   unsigned char	e_ident[EI_NIDENT];	/* Magic number and other info */
//   Elf64_Half	e_type;			/* Object file type */
//   Elf64_Half	e_machine;		/* Architecture */
//   Elf64_Word	e_version;		/* Object file version */
//   Elf64_Addr	e_entry;		/* Entry point virtual address */
//   Elf64_Off	e_phoff;		/* Program header table file offset */
//   Elf64_Off	e_shoff;		/* Section header table file offset */
//   Elf64_Word	e_flags;		/* Processor-specific flags */
//   Elf64_Half	e_ehsize;		/* ELF header size in bytes */
//   Elf64_Half	e_phentsize;		/* Program header table entry size */
//   Elf64_Half	e_phnum;		/* Program header table entry count */
//   Elf64_Half	e_shentsize;		/* Section header table entry size */
//   Elf64_Half	e_shnum;		/* Section header table entry count */
//   Elf64_Half	e_shstrndx;		/* Section header string table index */
// } Elf64_Ehdr;

    // First we have e_ident[16];
    char* copie = beginning_file;
    char version[4] = {0};
    memcpy(version, copie, 4);
    copie+=4;
    
    printf("[+Header] Check Magic Number : \n");
    // First 4 bytes are 0X7fELF for ELF file
    printf("Magic Number of the File : %s\n", version);

    printf("[+Header] Check 32 or 64 : \n");
    // Next one is the basically 64 or 32 bits.
    int8_t is32or64 = (int8_t)*copie;
    if(is32or64 == 1){
        printf("%d, It is 32 bits file\n", is32or64);
    } else if (is32or64 == 2){
        printf("%d, It is 64 bits file\n", is32or64);
    } else {
        printf("WTF is this file format\n");
    }
    copie+=1;

    printf("[+Header] Check Little or Big Endian : \n");
    // Next one is Little or Big endian
    int8_t isLittleorBig = (int8_t)*copie;
    if(isLittleorBig == 1){
        printf("%d, It is Little endian, LSB\n", isLittleorBig);
    } else if (isLittleorBig == 2){
        printf("%d, It is Big endian, MSB\n", isLittleorBig);
    } else {
        printf("WTF is this endian\n");
    }
    // nous sert plus tard pour la lecture des bytes
    isLittle = isLittleorBig % 2;
    copie+=1;

    printf("[+Header] Check 1 : \n");
    // Next one is 1, like really... 1...
    int8_t isOne= (int8_t)*copie;
    if(isOne == 1){
        printf("%d, C'est bien 1 bien vu\n", isOne);
    } else {
        printf("WHERE IS THE ONE\n");
    }
    copie+=1;

    printf("[+Header] Check OS system ABI : \n");
    // Next one is ABI check
    // List avec les bonnes values
    // on peut la mettre comme ça parce que les offsets se suivent bien
    char* ABI_List[18] = {
        "System V",
        "HP-UX",
        "NetBSD",
        "Linux",
        "GNU Hurd",
        "Solaris",
        "AIX (Monterey)",
        "IRIX",
        "FreeBSD",
        "Tru64",
        "Novell Modesto",
        "OpenBSD",
        "OpenVMS",
        "NonStop Kernel",
        "AROS",
        "FenixOS",
        "Nuxi CloudABI",
        "Stratus Technologies OpenVOS"
    };
    printf("OS ABI is %s\n", ABI_List[(int)*copie]);
    copie+=1;

    // Next one we don't rly care because normally the OSAPI value doesn't use this value anymore : https://docs.oracle.com/cd/E19683-01/816-1386/chapter6-35342/index.html
    copie+=1;

    // Next one we don't care it is reserved padding
    copie+=7;

    // e_type
    printf("[+Header] Check File type : \n");
    // !!!!  WARNING !!!! Endianess is used here 
    Elf64_Half* my_type = malloc(sizeof(Elf64_Half));
    // size = 2 ici
    read_byte_endian(copie, my_type, isLittle, sizeof(Elf64_Half));
    switch(*my_type) {
        case 0x00:
            printf("ET_NONE: Unknown.\n");
            break;
        case 0x01:
            printf("ET_REL: Relocatable file.\n");
            break;
        case 0x02:
            printf("ET_EXEC: Executable file. Statically linked.\n");
            break;
        case 0x03:
            printf("ET_DYN: Shared object. So Dynamically linked. \n");
            break;
        case 0x04:
            printf("ET_CORE: Core file.\n");
            break;
        default:
            if (*my_type >= 0xFE00 && *my_type <= 0xFEFF) {
                printf("OS-specific: ET_LOOS to ET_HIOS (0x%x)\n", *my_type);
            } else if (*my_type >= 0xFF00 && *my_type <= 0xFFFF) {
                printf("Processor-specific: ET_LOPROC to ET_HIPROC (0x%x)\n", *my_type);
            } else {
                printf("Nonono type: 0x%x\n", (uint16_t)*my_type);
            }
            break;
    }
    free(my_type);
    copie+=2;

    // E_machine 
    printf("[+Header] Check Instruction set Architecture : \n");
    Elf64_Half* my_machine = malloc(sizeof(Elf64_Half));
    read_byte_endian(copie, my_machine, isLittle, sizeof(Elf64_Half));
    switch(*my_machine) {
        case 0x00: printf("No specific instruction set\n"); break;
        case 0x01: printf("AT&T WE 32100\n"); break;
        case 0x02: printf("SPARC\n"); break;
        case 0x03: printf("x86\n"); break;
        case 0x04: printf("Motorola 68000 (M68k)\n"); break;
        case 0x05: printf("Motorola 88000 (M88k)\n"); break;
        case 0x06: printf("Intel MCU\n"); break;
        case 0x07: printf("Intel 80860\n"); break;
        case 0x08: printf("MIPS\n"); break;
        case 0x09: printf("IBM System/370\n"); break;
        case 0x0A: printf("MIPS RS3000 Little-endian\n"); break;
        case 0x0F: printf("Hewlett-Packard PA-RISC\n"); break;
        case 0x13: printf("Intel 80960\n"); break;
        case 0x14: printf("PowerPC\n"); break;
        case 0x15: printf("PowerPC (64-bit)\n"); break;
        case 0x16: printf("S390, including S390x\n"); break;
        case 0x17: printf("IBM SPU/SPC\n"); break;
        case 0x24: printf("NEC V800\n"); break;
        case 0x25: printf("Fujitsu FR20\n"); break;
        case 0x26: printf("TRW RH-32\n"); break;
        case 0x27: printf("Motorola RCE\n"); break;
        case 0x28: printf("Arm (up to Armv7/AArch32)\n"); break;
        case 0x29: printf("Digital Alpha\n"); break;
        case 0x2A: printf("SuperH\n"); break;
        case 0x2B: printf("SPARC Version 9\n"); break;
        case 0x2C: printf("Siemens TriCore embedded processor\n"); break;
        case 0x2D: printf("Argonaut RISC Core\n"); break;
        case 0x2E: printf("Hitachi H8/300\n"); break;
        case 0x2F: printf("Hitachi H8/300H\n"); break;
        case 0x30: printf("Hitachi H8S\n"); break;
        case 0x31: printf("Hitachi H8/500\n"); break;
        case 0x32: printf("IA-64\n"); break;
        case 0x33: printf("Stanford MIPS-X\n"); break;
        case 0x34: printf("Motorola ColdFire\n"); break;
        case 0x35: printf("Motorola M68HC12\n"); break;
        case 0x36: printf("Fujitsu MMA Multimedia Accelerator\n"); break;
        case 0x37: printf("Siemens PCP\n"); break;
        case 0x38: printf("Sony nCPU embedded RISC processor\n"); break;
        case 0x39: printf("Denso NDR1 microprocessor\n"); break;
        case 0x3A: printf("Motorola Star*Core processor\n"); break;
        case 0x3B: printf("Toyota ME16 processor\n"); break;
        case 0x3C: printf("STMicroelectronics ST100 processor\n"); break;
        case 0x3D: printf("Advanced Logic Corp. TinyJ embedded processor family\n"); break;
        case 0x3E: printf("AMD x86-64\n"); break;
        case 0x3F: printf("Sony DSP Processor\n"); break;
        case 0x40: printf("Digital Equipment Corp. PDP-10\n"); break;
        case 0x41: printf("Digital Equipment Corp. PDP-11\n"); break;
        case 0x42: printf("Siemens FX66 microcontroller\n"); break;
        case 0x43: printf("STMicroelectronics ST9+ 8/16 bit microcontroller\n"); break;
        case 0x44: printf("STMicroelectronics ST7 8-bit microcontroller\n"); break;
        case 0x45: printf("Motorola MC68HC16 Microcontroller\n"); break;
        case 0x46: printf("Motorola MC68HC11 Microcontroller\n"); break;
        case 0x47: printf("Motorola MC68HC08 Microcontroller\n"); break;
        case 0x48: printf("Motorola MC68HC05 Microcontroller\n"); break;
        case 0x49: printf("Silicon Graphics SVx\n"); break;
        case 0x4A: printf("STMicroelectronics ST19 8-bit microcontroller\n"); break;
        case 0x4B: printf("Digital VAX\n"); break;
        case 0x4C: printf("Axis Communications 32-bit embedded processor\n"); break;
        case 0x4D: printf("Infineon Technologies 32-bit embedded processor\n"); break;
        case 0x4E: printf("Element 14 64-bit DSP Processor\n"); break;
        case 0x4F: printf("LSI Logic 16-bit DSP Processor\n"); break;
        case 0x8C: printf("TMS320C6000 Family\n"); break;
        case 0xAF: printf("MCST Elbrus e2k\n"); break;
        case 0xB7: printf("Arm 64-bits (Armv8/AArch64)\n"); break;
        case 0xDC: printf("Zilog Z80\n"); break;
        case 0xF3: printf("RISC-V\n"); break;
        case 0xF7: printf("Berkeley Packet Filter\n"); break;
        case 0x101: printf("WDC 65C816\n"); break;
        case 0x102: printf("LoongArch\n"); break;

        default:
            printf("Alors là t'abuses j'ai tout mis: 0x%x\n", (uint16_t)*my_machine);
            break;
    }
    free(my_machine);
    copie+=2;

    // e_version
    // check if one
    printf("[+Header] Check 1 Again for current version : \n");
    Elf64_Word* my_version = malloc(sizeof(Elf64_Word));
    read_byte_endian(copie, my_version, isLittle, sizeof(Elf64_Word));
    if(*my_version == 1){
        printf("Check 1 OK \n");
    } else {
        printf("DIDNT PASS CHECK 1 \n");
    }
    free(my_version);
    copie+=4;

    // e_entry
    printf("[+Header] Check virtual entry point address : \n");
    Elf64_Addr* my_entry = malloc(sizeof(Elf64_Addr));
    read_byte_endian(copie, my_entry, isLittle, sizeof(Elf64_Addr));
    printf("Virual entry address is 0x%lx\n", (uint64_t)*my_entry);
    free(my_entry);
    copie+=8;

    // e_phoff  c'est l'offset depuis le début du fichier pour tombé sur les programs
    // Ils sont tous alignés MEME TAILLE + A LA SUITE !!
    // c'est pour ça qu'on va récup, où est le premier, cmb y'en a, et la taille 
    printf("[+Header] Check Program header offset  : \n");
    read_byte_endian(copie, ph_off, isLittle, sizeof(Elf64_Off));
    printf("Program Header offset is 0x%lx\n", (uint64_t)*ph_off);
    // généralement 0x40 c'est genre juste après notre header ELF
    copie+=8;

    // e_shoff c'est l'offset pour le premier section header !
    printf("[+Header] Check Section header offset  : \n");
    read_byte_endian(copie, sh_off, isLittle, sizeof(Elf64_Off));
    printf("Section Header offset is 0x%lx\n", (uint64_t)*sh_off);
    // généralement 0x40 c'est genre juste après notre header ELF
    copie+=8;

    // e_flags
    printf("[+Header] Check flags specific for archictecture : \n");
    Elf64_Word* my_flags = malloc(sizeof(Elf64_Word));
    read_byte_endian(copie, my_flags, isLittle, sizeof(Elf64_Word));
    printf("Flags are 0x%x\n", (uint32_t)*my_flags);
    free(my_flags);
    copie+=4;

    // e_ehsize
    printf("[+Header] Check size of this header (should be 64 or 52) : \n");
    Elf64_Half* my_ehsize = malloc(sizeof(Elf64_Half));
    read_byte_endian(copie, my_ehsize, isLittle, sizeof(Elf64_Half));
    printf("Size of the ELF header: %d\n", *my_ehsize);
    free(my_ehsize);
    copie+=2;

    // e_phentsize 
    printf("[+Header] Check Program Header table entry size (should be 32 or 56) : \n");
    Elf64_Half* my_phentsize = malloc(sizeof(Elf64_Half));
    read_byte_endian(copie, my_phentsize, isLittle, sizeof(Elf64_Half));
    printf("Size of the One Program Header table: %d\n", (uint16_t)*my_phentsize);
    free(my_phentsize);
    copie+=2;

    // e_phnum 
    // on a la taille et le nombre de page, on pourrait calculer la place
    // totale que prend les programs header en faisant la multiplication
    printf("[+Header] Check Number of Program Header table : \n");
    read_byte_endian(copie, ph_num, isLittle, sizeof(Elf64_Half));
    printf("Number of Program Header table: %d\n", (uint16_t)*ph_num);
    copie+=2;

    // e_shentsize
    printf("[+Header] Check Section Header table entry size (should be 40 or 64) : \n");
    Elf64_Half* my_shentsize = malloc(sizeof(Elf64_Half));
    read_byte_endian(copie, my_shentsize, isLittle, sizeof(Elf64_Half));
    printf("Size of the One Section Header table: %d\n", (uint16_t)*my_shentsize);
    free(my_shentsize);
    copie+=2;

    // e_shnum
    printf("[+Header] Check Number of Section Header table : \n");
    read_byte_endian(copie, sh_num, isLittle, sizeof(Elf64_Half));
    printf("Number of Section Header table: %d\n", (uint16_t)*sh_num);
    copie+=2;

    // e_shstrndx
    // chaque section ne connait pas son propre nom amis à un offset dans cette table
    // pour savoir son nom
    // pratique car  Les Section Headers gardent une structure fixe, facile à parser, à copier, à aligner en mémoire.
    // Sinon avec les noms ça bougerait tous donc c'est relou
    printf("[+Header] Check index of the section header table entry that contains the section names (.shstrtab) : \n");
    read_byte_endian(copie, sh_shs, isLittle, sizeof(Elf64_Half));
    printf("Index of the .shstrtab table in the sections headers : %d\n", (uint16_t)*sh_shs);
    copie+=2;
    // donc la on a dans tous les sections le numéro de laquelle est celle de .shstrtab
    // ils sont aussi collés comme les programs headers
    return; 
}

void read_byte_endian(char* start, void* mavar, bool isLittle, int size){
    char tampon[8];

    if (size > 8 || size < 1) {
        printf("WTF IS THIS SIZE BRO\n");
        return;
    }

    for(int i = 0; i < size; i++) {
        // Je ne dois RIEN changer si c'est un binaire en little endian parce que ma machine interprète deja les vars en little endian
        // Si vous avez une machineen big endian il va falloir inverser le statement
        tampon[i] = isLittle ? start[i] : start[size - 1 - i];
    }

    switch(size) {
        case 2:
            memcpy(mavar, tampon, 2);
            break;
        case 4:
            memcpy(mavar, tampon, 4);
            break;
        case 8:
            memcpy(mavar, tampon, 8);
            break;
        default:
            printf("Nope\n");
    }
    return;
}

void getInfoProgramHeader(char* beginning_ph, Elf64_Half ph_num){

//     typedef struct {
// 	Elf64_Word	p_type;
// 	Elf64_Word	p_flags;
// 	Elf64_Off	p_offset;
// 	Elf64_Addr	p_vaddr;
// 	Elf64_Addr	p_paddr;
// 	Elf64_Xword	p_filesz;
// 	Elf64_Xword	p_memsz;
// 	Elf64_Xword	p_align;
// } Elf64_Phdr;

    Elf64_Word*	p_type = malloc(sizeof(Elf64_Word));
    Elf64_Word*	p_flags = malloc(sizeof(Elf64_Word));
    Elf64_Off*	p_offset = malloc(sizeof(Elf64_Off));
    Elf64_Addr*	p_vaddr = malloc(sizeof(Elf64_Addr));
    Elf64_Addr*	p_paddr = malloc(sizeof(Elf64_Addr));
    Elf64_Xword*	p_filesz = malloc(sizeof(Elf64_Xword));
    Elf64_Xword*	p_memsz = malloc(sizeof(Elf64_Xword));
    Elf64_Xword*	p_align = malloc(sizeof(Elf64_Xword));

    // se charge de dire quel block à quelles permissions et va où
    char* copie = beginning_ph;
    for(int i = 0; i < ph_num; i++){
        printf("[+] Program Header number %d, start !\n\n", i);

        // p_type
        printf("[+ Program Header] Check Segment type : \n");
        read_byte_endian(copie, p_type, isLittle, sizeof(Elf64_Word));
        switch(*p_type) {
            case 0x00000000:
                printf("PT_NULL: Program header table entry unused.\n");
                break;
            case 0x00000001:
                printf("PT_LOAD: Loadable segment.\n");
                break;
            case 0x00000002:
                printf("PT_DYNAMIC: Dynamic linking information.\n");
                break;
            case 0x00000003:
                printf("PT_INTERP: Interpreter information.\n");
                break;
            case 0x00000004:
                printf("PT_NOTE: Auxiliary information.\n");
                break;
            case 0x00000005:
                printf("PT_SHLIB: Reserved.\n");
                break;
            case 0x00000006:
                printf("PT_PHDR: Segment containing program header table itself.\n");
                break;
            case 0x00000007:
                printf("PT_TLS: Thread-Local Storage template.\n");
                break;
            default:
                if (*p_type >= 0x60000000 && *p_type <= 0x6FFFFFFF) {
                    printf("Reserved inclusive range. Operating system specific. Do NOT take into account the next analysis. (0x%x)\n", *p_type);
                } else if (*p_type >= 0x70000000 && *p_type <= 0x7FFFFFFF) {
                    printf("Reserved inclusive range. Processor specific. Do NOT take into account the next analysis. (0x%x)\n", *p_type);
                } else {
                    printf("Nonono type: 0x%x\n", (uint32_t)*p_type);
                }
                break;
        }
        copie+=4;

        // p_flags
        printf("[+ Program Header] Check Flags : \n");
        read_byte_endian(copie, p_flags, isLittle, sizeof(Elf64_Word));
        switch(*p_flags) {
            case 0x00000000:
                printf("All Access deny, Read Write AND execute\n");
                break;
            case 0x00000001:
                printf("Execute Only.\n");
                break;
            case 0x00000002:
                printf("Write Only.\n");
                break;
            case 0x00000003:
                printf("Write AND Execute.\n");
                break;
            case 0x00000004:
                printf("Read Only.\n");
                break;
            case 0x00000005:
                printf("Read AND Execute.\n");
                break;
            case 0x00000006:
                printf("Read AND Write.\n");
                break;
            case 0x00000007:
                printf("Read AND Write AND Execute.\n");
                break;
            default:
                printf("NOOOOOOO\n");
                break;
        }
        copie+=4;

        // p_offset
        // This member gives the offset from the beginning of the file at which the first byte of the segment resides.
        printf("[+ Program Header] Check Offset : \n");
        read_byte_endian(copie, p_offset, isLittle, sizeof(Elf64_Off));
        printf("Offset of Program Header number %d is 0x%lx\n", i, (uint64_t)*p_offset);
        copie+=8;

        // p_vaddr
        // This member gives the virtual address at which the first byte of the segment resides in memory.
        printf("[+ Program Header] Check Virtual Adress : \n");
        read_byte_endian(copie, p_vaddr, isLittle, sizeof(Elf64_Addr));
        printf("Vaddr of Program Header number%d is 0x%lx\n", i, (uint64_t)*p_vaddr);
        copie+=8;

        // p_paddr 
        // On systems for which physical addressing is relevant, this member is reserved for the segment's physical address. Because System V ignores physical addressing for application programs, this member has unspecified contents for executable files and shared objects.
        printf("[+ Program Header] Check Physical Adress (certainly not relevant here): \n");
        read_byte_endian(copie, p_paddr, isLittle, sizeof(Elf64_Addr));
        printf("Paddr of Program Header number %d is 0x%lx\n", i, (uint64_t)*p_paddr);
        copie+=8;

        // p_filesz
        // This member gives the number of bytes in the file image of the segment; it may be zero.
        printf("[+ Program Header] Check Size in the file : \n");
        read_byte_endian(copie, p_filesz, isLittle, sizeof(Elf64_Xword));
        printf("Size in the file of PH number %d is 0x%lx\n", i, (uint64_t)*p_filesz);
        copie+=8;

        // p_memsz 
        // This member gives the number of bytes in the memory image of the segment; it may be zero.
        printf("[+ Program Header] Check Size needed in the memory : \n");
        read_byte_endian(copie, p_memsz, isLittle, sizeof(Elf64_Xword));
        printf("Size in the memory of PH number %d is 0x%lx\n", i, (uint64_t)*p_memsz);
        copie+=8;
        // Why p_memsz can be different than p_filesz. .BSS section where we have an uninitialized 
        // variable with 1000 bytes, so p_filesz = 0 because we are not going to write
        // 1000 0 on the file but p_memsz = 1000


        // p_align
        // (p_vaddr % p_align) == (p_offset % p_align) parce que on va charger les pages entières
        // pour que ça soit aligner
        // enft on va faire ça pour que notre code soit bien dans des pages (4ko souvent)
        // et donc mmap va pouvoir les mettre super efficacement en RAM
        // sinon il faudrait créer une page vide, copier les bytes, et faire mmap ce qui est super long et casse les opti
        // donc on refuse d'autoriser de faire ça.

        // question : pourquoi quand je fais un mmap d'un fichier en C je me préocupe pas de si il est bien aligné dans des pages ou pas ? 
        // réponse : Quand TU fais un mmap() dans ton code C, c’est pas pareil que quand le KERNEL fait un mmap() pour charger un ELF.
        // Il doit mapper une partie du fichier à une adresse mémoire précise (celle donnée par p_vaddr)
        // En plus comme c'est du code éxécutable c'est encore plus important d'avoir un bon aligment sinon ça peut tout casser.

        printf("[+ Program Header] Check Align : \n");
        read_byte_endian(copie, p_align, isLittle, sizeof(Elf64_Xword));
        if(*p_align == 0 || *p_align == 1){
            //  no specific alignment
            printf("No specific alignment for this Program piece number %d\n\n",i);
        } else {
            printf("Size of specific alignment for Program piece number %d is 0x%lx\n\n", i,*p_align);
        }
        copie+=8;

        printf("[+] Program Header number %d, end !\n", i);
    }

    // free
    free(p_type);
    free(p_flags);
    free(p_offset);
    free(p_vaddr);
    free(p_paddr);
    free(p_filesz);
    free(p_memsz);
    free(p_align);

    return;
}

void getInfoSectionHeader(char* beginning, Elf64_Off sh_offset, Elf64_Half sh_number, Elf64_Half sh_shs){
    // typedef struct
    // {
    // Elf64_Word	sh_name;		/* Section name (string tbl index) */
    // Elf64_Word	sh_type;		/* Section type */
    // Elf64_Xword	sh_flags;		/* Section flags */
    // Elf64_Addr	sh_addr;		/* Section virtual addr at execution */
    // Elf64_Off	sh_offset;		/* Section file offset */
    // Elf64_Xword	sh_size;		/* Section size in bytes */
    // Elf64_Word	sh_link;		/* Link to another section */
    // Elf64_Word	sh_info;		/* Additional section information */
    // Elf64_Xword	sh_addralign;		/* Section alignment */
    // Elf64_Xword	sh_entsize;		/* Entry size if section holds table */
    // } Elf64_Shdr;
    // taille de 64 bytes pour 64 bits

    // malloc
    Elf64_Word*	s_name = malloc(sizeof(Elf64_Word));
    Elf64_Word*	s_type = malloc(sizeof(Elf64_Word));
    Elf64_Xword*	s_flags = malloc(sizeof(Elf64_Xword));	
    Elf64_Addr*	s_addr = malloc(sizeof(Elf64_Addr));	
    Elf64_Off*	s_offset = malloc(sizeof(Elf64_Off));	
    Elf64_Xword*	s_size = malloc(sizeof(Elf64_Xword));
    Elf64_Word*	s_link = malloc(sizeof(Elf64_Word));
    Elf64_Word*	s_info = malloc(sizeof(Elf64_Word));
    Elf64_Xword*	s_addralign = malloc(sizeof(Elf64_Xword));
    Elf64_Xword*	s_entsize = malloc(sizeof(Elf64_Xword));	

    // On va commencer par la table .shstrtab pour avoir tous les noms
    char* beginning_sh = beginning + sh_offset;
    //  la taille c'est celle pour 64 bits
    int size64bits_sh = 64;
    char* start_shs = beginning_sh + size64bits_sh*sh_shs;
    printf("[+] Analyse de .shstrtab \n");

    // sh_name
    // offset dans .shstrtab pour connaître son nommm
    printf("[+ Section Header] Check de l'offset dans .shstrtab :\n");
    read_byte_endian(start_shs, s_name, isLittle, sizeof(Elf64_Word));
    printf("Offset dans la table .shstrtab : 0x%x\n", (uint32_t)*s_name);
    start_shs+=4;

    // sh_type 
    // la section qu'on pointe sert à/fait quoi en gros
    printf("[+ Section Header] Check du type :\n");
    read_byte_endian(start_shs, s_type, isLittle, sizeof(Elf64_Word));
    switch (*s_type) {
        case 0:  printf("SHT_NULL: Section header inactive\n"); break;
        case 1:  printf("SHT_PROGBITS: Program data\n"); break;
        case 2:  printf("SHT_SYMTAB: Symbol table\n"); break;
        case 3:  printf("SHT_STRTAB: String table\n"); break;
        case 4:  printf("SHT_RELA: Relocation entries with addends\n"); break;
        case 5:  printf("SHT_HASH: Symbol hash table\n"); break;
        case 6:  printf("SHT_DYNAMIC: Dynamic linking information\n"); break;
        case 7:  printf("SHT_NOTE: Notes\n"); break;
        case 8:  printf("SHT_NOBITS: Program space with no data (bss)\n"); break;
        case 9:  printf("SHT_REL: Relocation entries without addends\n"); break;
        case 10: printf("SHT_SHLIB: Reserved\n"); break;
        case 11: printf("SHT_DYNSYM: Dynamic linker symbol table\n"); break;
        case 14: printf("SHT_INIT_ARRAY: Array of constructors\n"); break;
        case 15: printf("SHT_FINI_ARRAY: Array of destructors\n"); break;
        case 16: printf("SHT_PREINIT_ARRAY: Array of pre-constructors\n"); break;
        case 17: printf("SHT_GROUP: Section group\n"); break;
        case 18: printf("SHT_SYMTAB_SHNDX: Extended section indices\n"); break;

        default:
            if (*s_type >= 0x60000000 && *s_type <= 0x6fffffff) {
                printf("OS-specific section type (SHT_LOOS - SHT_HIOS): 0x%x\n", (uint32_t)*s_type);
            } else if (*s_type >= 0x70000000 && *s_type <= 0x7fffffff) {
                printf("Processor-specific section type (SHT_LOPROC - SHT_HIPROC): 0x%x\n", (uint32_t)*s_type);
            } else if (*s_type >= 0x80000000 && *s_type <= 0xffffffff) {
                printf("Application-specific section type (SHT_LOUSER - SHT_HIUSER): 0x%x\n", (uint32_t)*s_type);
            } else {
                printf("Je sais pas comment interpréter ça : 0x%x\n", (uint32_t)*s_type);
            }
            break;
    }
    start_shs+=4;

    // sh_flags
    // différents flags pour avoir plus d'infos sur notre sections
    printf("[+ Section Header] Check du Flag : \n");
    read_byte_endian(start_shs, s_flags, isLittle, sizeof(Elf64_Xword));
    if (*s_flags & 0x1)
        printf("SHF_WRITE: Section contains writable data (during process exec)\n");
    if (*s_flags & 0x2)
        printf("SHF_ALLOC: The section occupies memory during process execution.\n");
    if (*s_flags & 0x4)
        printf("SHF_EXECINSTR: Section contains executable instructions\n");
    if (*s_flags & 0x10)
        printf("SHF_MERGE: Section may be merged to eliminate duplication\n");
    if (*s_flags & 0x20)
        printf("SHF_STRINGS: Section contains null-terminated strings\n");
    if (*s_flags & 0x40)
        printf("SHF_INFO_LINK: sh_info holds a section header table index\n");
    if (*s_flags & 0x80)
        printf("SHF_LINK_ORDER: Preserve section ordering when linking\n");
    if (*s_flags & 0x100)
        printf("SHF_OS_NONCONFORMING: OS-specific processing required\n");
    if (*s_flags & 0x200)
        printf("SHF_GROUP: Section is part of a section group\n");
    if (*s_flags == 0)
        printf("Y'a rien comme flag.\n");
    start_shs+=8;

    // sh_addr 
    // this member gives the address at which the section's first byte should reside (if needed to be in memory)
    printf("[+ Section Header] Check de l'addr virtuelle : \n");
    read_byte_endian(start_shs, s_addr, isLittle, sizeof(Elf64_Addr));
    printf("Virtual addr of this section is 0x%lx\n", (uint64_t)*s_addr);
    start_shs+=8;

    // sh_offset
    // This member's value gives the byte offset from the beginning of the file to the first byte in the section
    printf("[+ Section Header] Check de l'offset dans le fichier : \n");
    read_byte_endian(start_shs, s_offset, isLittle, sizeof(Elf64_Off));
    printf("Offset of this section is 0x%lx\n", (uint64_t)*s_offset);
    start_shs+=8;

    // sh_size
    // nombre d'octets de la section, simple
    printf("[+ Section Header] Check de la taille de la section : \n");
    read_byte_endian(start_shs, s_size, isLittle, sizeof(Elf64_Xword));
    printf("Size of the Section in bytes is 0x%lx\n", (uint64_t)*s_size);
    start_shs+=8;

    // sh_link
    // sh_info
    // Donne des infos qui dépendent du sh-type
    start_shs+=8;

    // sh_addralign
    // if special alignment required specified here
    printf("[+ Section Header] Check Align : \n");
    read_byte_endian(start_shs, s_addralign, isLittle, sizeof(Elf64_Xword));
    if(*s_addralign == 0 || *s_addralign == 1){
        //  no specific alignment
        // Values 0 and 1 mean the section has no alignment constraints : https://www.sco.com/developers/gabi/2000-07-17/ch4.sheader.html#sh_link
        // Cette précision n'est pas faite par readelf 
        printf("No specific alignment for this Section\n");
    } else {
        printf("Size of specific alignment for this Section is 0x%lx\n",*s_addralign);
    }
    start_shs+=8;

    // sh_entsize
    // Some sections hold a table of fixed-size entries, such as a symbol table. For such a section, this member gives the size in bytes of each entry
    printf("[+ Section Header] Check Fixed-Size entries : \n");
    read_byte_endian(start_shs, s_entsize, isLittle, sizeof(Elf64_Xword));
    if(*s_entsize == 0){
        //  no fixe size entry
        printf("No specific size entry this Section\n\n");
    } else {
        printf("Size of fixed-size entries for this Section is 0x%lx\n\n",*s_entsize);
    }

    // TROUVER LE NOM 
    // on réserve la place pour copier la chiane de caractère
    char *ch_shstrtab = malloc(*s_size);
    // on charge la table
    memcpy(ch_shstrtab, beginning + *s_offset, *s_size);

    // et on peut print !
    printf("Nom de la table .shstrtab : %s\n\n", ch_shstrtab+*s_name);

    // c'est parti pour les autres
    // ils semblent que .shstrtab est toujours le dernier, on va juste être s'assurer de ça avant de lancer la boucle

    if(sh_number == sh_shs + 1){
        printf(".shstrtab est bien à la fin");
    } else {
        printf(".shstrtab n'est pas à la fin, ce n'est pas encore pris en charge (tu peux l'implémenter c'est pas très difficile)");
        return;
    }

    for(int i=0; i<sh_shs; i++){
        // checker les autres sections headers.

        // on va réutiliser beginning_sh

        printf("[+] Analyse de la section header numéro %d \n\n", i);

        // sh_name
        // offset dans .shstrtab pour connaître son nommm
        printf("[+ Section Header] Check de l'offset dans .shstrtab :\n");
        read_byte_endian(beginning_sh, s_name, isLittle, sizeof(Elf64_Word));
        printf("Offset dans la table .shstrtab : 0x%x\n", (uint32_t)*s_name);
        printf("===> Nom de la table .shstrtab : %s\n", ch_shstrtab+*s_name);
        beginning_sh+=4;

        // sh_type 
        // la section qu'on pointe sert à/fait quoi en gros
        printf("[+ Section Header] Check du type :\n");
        read_byte_endian(beginning_sh, s_type, isLittle, sizeof(Elf64_Word));
        switch (*s_type) {
            case 0:  printf("SHT_NULL: Section header inactive\n"); break;
            case 1:  printf("SHT_PROGBITS: Program data\n"); break;
            case 2:  printf("SHT_SYMTAB: Symbol table\n"); break;
            case 3:  printf("SHT_STRTAB: String table\n"); break;
            case 4:  printf("SHT_RELA: Relocation entries with addends\n"); break;
            case 5:  printf("SHT_HASH: Symbol hash table\n"); break;
            case 6:  printf("SHT_DYNAMIC: Dynamic linking information\n"); break;
            case 7:  printf("SHT_NOTE: Notes\n"); break;
            case 8:  printf("SHT_NOBITS: Program space with no data (bss)\n"); break;
            case 9:  printf("SHT_REL: Relocation entries without addends\n"); break;
            case 10: printf("SHT_SHLIB: Reserved\n"); break;
            case 11: printf("SHT_DYNSYM: Dynamic linker symbol table\n"); break;
            case 14: printf("SHT_INIT_ARRAY: Array of constructors\n"); break;
            case 15: printf("SHT_FINI_ARRAY: Array of destructors\n"); break;
            case 16: printf("SHT_PREINIT_ARRAY: Array of pre-constructors\n"); break;
            case 17: printf("SHT_GROUP: Section group\n"); break;
            case 18: printf("SHT_SYMTAB_SHNDX: Extended section indices\n"); break;

            default:
                if (*s_type >= 0x60000000 && *s_type <= 0x6fffffff) {
                    printf("OS-specific section type (SHT_LOOS - SHT_HIOS): 0x%x\n", (uint32_t)*s_type);
                } else if (*s_type >= 0x70000000 && *s_type <= 0x7fffffff) {
                    printf("Processor-specific section type (SHT_LOPROC - SHT_HIPROC): 0x%x\n", (uint32_t)*s_type);
                } else if (*s_type >= 0x80000000 && *s_type <= 0xffffffff) {
                    printf("Application-specific section type (SHT_LOUSER - SHT_HIUSER): 0x%x\n", (uint32_t)*s_type);
                } else {
                    printf("Je sais pas comment interpréter ça : 0x%x\n", (uint32_t)*s_type);
                }
                break;
        }
        beginning_sh+=4;

        // sh_flags
        // différents flags pour avoir plus d'infos sur notre sections
        printf("[+ Section Header] Check du Flag : \n");
        read_byte_endian(beginning_sh, s_flags, isLittle, sizeof(Elf64_Xword));
        if (*s_flags & 0x1)
            printf("SHF_WRITE: Section contains writable data (during process exec)\n");
        if (*s_flags & 0x2)
            printf("SHF_ALLOC: The section occupies memory during process execution.\n");
        if (*s_flags & 0x4)
            printf("SHF_EXECINSTR: Section contains executable instructions\n");
        if (*s_flags & 0x10)
            printf("SHF_MERGE: Section may be merged to eliminate duplication\n");
        if (*s_flags & 0x20)
            printf("SHF_STRINGS: Section contains null-terminated strings\n");
        if (*s_flags & 0x40)
            printf("SHF_INFO_LINK: sh_info holds a section header table index\n");
        if (*s_flags & 0x80)
            printf("SHF_LINK_ORDER: Preserve section ordering when linking\n");
        if (*s_flags & 0x100)
            printf("SHF_OS_NONCONFORMING: OS-specific processing required\n");
        if (*s_flags & 0x200)
            printf("SHF_GROUP: Section is part of a section group\n");
        if (*s_flags == 0)
            printf("Y'a rien comme flag.\n");
        beginning_sh+=8;

        // sh_addr 
        // this member gives the address at which the section's first byte should reside (if needed to be in memory)
        printf("[+ Section Header] Check de l'addr virtuelle : \n");
        read_byte_endian(beginning_sh, s_addr, isLittle, sizeof(Elf64_Addr));
        printf("Virtual addr of this section is 0x%lx\n", (uint64_t)*s_addr);
        beginning_sh+=8;

        // sh_offset
        // This member's value gives the byte offset from the beginning of the file to the first byte in the section
        printf("[+ Section Header] Check de l'offset dans le fichier : \n");
        read_byte_endian(beginning_sh, s_offset, isLittle, sizeof(Elf64_Off));
        printf("Offset of this section is 0x%lx\n", (uint64_t)*s_offset);
        beginning_sh+=8;

        // sh_size
        // nombre d'octets de la section, simple
        printf("[+ Section Header] Check de la taille de la section : \n");
        read_byte_endian(beginning_sh, s_size, isLittle, sizeof(Elf64_Xword));
        printf("Size of the Section in bytes is 0x%lx\n", (uint64_t)*s_size);
        beginning_sh+=8;

        // sh_link
        // sh_info
        // Donne des infos qui dépendent du sh-type
        beginning_sh+=8;

        // sh_addralign
        // if special alignment required specified here
        printf("[+ Section Header] Check Align : \n");
        read_byte_endian(beginning_sh, s_addralign, isLittle, sizeof(Elf64_Xword));
        if(*s_addralign == 0 || *s_addralign == 1){
            //  no specific alignment
            // Values 0 and 1 mean the section has no alignment constraints : https://www.sco.com/developers/gabi/2000-07-17/ch4.sheader.html#sh_link
            // Cette précision n'est pas faite par readelf 
            printf("No specific alignment for this Section\n");
        } else {
            printf("Size of specific alignment for this Section is 0x%lx\n",*s_addralign);
        }
        beginning_sh+=8;

        // sh_entsize
        // Some sections hold a table of fixed-size entries, such as a symbol table. For such a section, this member gives the size in bytes of each entry
        printf("[+ Section Header] Check Fixed-Size entries : \n");
        read_byte_endian(beginning_sh, s_entsize, isLittle, sizeof(Elf64_Xword));
        if(*s_entsize == 0){
            //  no fixe size entry
            printf("No specific size entry this Section\n\n");
        } else {
            printf("Size of fixed-size entries for this Section is 0x%lx\n\n",*s_entsize);
        }
        beginning_sh+=8;

        printf("[+] Fin de l'Analyse de la section header numéro %d \n\n", i);
    }

    // free
    free(s_name);
    free(s_type);
    free(s_flags);	
    free(s_addr);	
    free(s_offset);	
    free(s_size);
    free(s_link);
    free(s_info);
    free(s_addralign);
    free(s_entsize);

    // free ad_hoc
    free(ch_shstrtab);
    return;
}