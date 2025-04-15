#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h> // 3 premiers include qui vienne de map open
#include <stdio.h> // printf
#include <stdlib.h>
#include <sys/mman.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

/* Type for a 16-bit quantity.  */
typedef uint16_t Elf32_Half;
typedef uint16_t Elf64_Half;

/* Types for signed and unsigned 32-bit quantities.  */
typedef uint32_t Elf32_Word;
typedef	int32_t  Elf32_Sword;
typedef uint32_t Elf64_Word;
typedef	int32_t  Elf64_Sword;

/* Types for signed and unsigned 64-bit quantities.  */
typedef uint64_t Elf32_Xword;
typedef	int64_t  Elf32_Sxword;
typedef uint64_t Elf64_Xword;
typedef	int64_t  Elf64_Sxword;

/* Type of addresses.  */
typedef uint32_t Elf32_Addr;
typedef uint64_t Elf64_Addr;

/* Type of file offsets.  */
typedef uint32_t Elf32_Off;
typedef uint64_t Elf64_Off;

/* Type for section indices, which are 16-bit quantities.  */
typedef uint16_t Elf32_Section;
typedef uint16_t Elf64_Section;

/* Type for version symbol information.  */
typedef Elf32_Half Elf32_Versym;
typedef Elf64_Half Elf64_Versym;


// Fonction qui retourne un pointeur vers le contenu mappé du fichier ELF
char* get_my_file(char* filename);

// Fonction qui lit les premières infos de l'entête ELF
void getInfoHeader(char* beginning_file, Elf64_Off* ph_off, Elf64_Half* ph_num, Elf64_Off* sh_off, Elf64_Half* sh_num, Elf64_Half* sh_shs);

// Function qui lit les Programs Header 
void getInfoProgramHeader(char* beginning_ph, Elf64_Half ph_num);

// Function qui lit les Sections Header
void getInfoSectionHeader(char* beginning, Elf64_Off shàoffset, Elf64_Half sh_number, Elf64_Half sh_shs);

// Function qui lui lit les bits en fct de l'endianness
void read_byte_endian(char* start, void* mavar, bool isLittle, int size);