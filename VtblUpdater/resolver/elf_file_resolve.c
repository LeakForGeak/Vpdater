
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#include "../elf64/elf64.h"
#include "../utils/file_utils.h"

#define SHT_SYMTAB 0x2
#define SHT_DYNSYM 0xb

typedef int res_result;


int rva2foa(const char* bytes, int target_rva){
    int target_foa = -1;

    Elf64_Ehdr* pElf64_Ehdr = (Elf64_Ehdr*)(bytes);
    Elf64_Shdr* pElf64_Shdr = (Elf64_Shdr*)(bytes + pElf64_Ehdr->e_shoff);

    for(int i = 0;i < pElf64_Ehdr->e_shnum; i++){
        if((target_rva >= pElf64_Shdr->sh_addr) && (target_rva <= (pElf64_Shdr->sh_addr + pElf64_Shdr->sh_size))){
            target_foa = target_rva - pElf64_Shdr->sh_addr;
            target_foa += pElf64_Shdr->sh_offset;
        }
        pElf64_Shdr++;
    }

    return target_foa;
}

char* dyn_symbol[];

//output function
void print_sections_with_rva(const char* bytes) {

    uintptr_t dynstr_offset = -1;

    Elf64_Ehdr* pElf64_Ehdr = (Elf64_Ehdr*)bytes;

    // Get section header table
    Elf64_Shdr* section_headers = (Elf64_Shdr*)(bytes + pElf64_Ehdr->e_shoff);

    // Find the string table section
    Elf64_Shdr* string_table_section = &section_headers[pElf64_Ehdr->e_shstrndx];
    const char* string_table = bytes + string_table_section->sh_offset;

    printf("Section Index\tSection Name\t\t      RVA\n");
    for (int i = 0; i < pElf64_Ehdr->e_shnum; ++i) {
        const char* section_name = string_table + section_headers[i].sh_name;
         printf("%d\t\t%-30s0x%x\n", i, section_name, section_headers[i].sh_addr);
        if(strcmp(section_name, ".gnu_debuglink") == 0){
            unsigned int debug_link_offset = section_headers[i].sh_offset;
            unsigned int debug_link_size = section_headers[i].sh_size;

            // Print the bytes of .gnu_debuglink section
            printf("Contents of .gnu_debuglink section:\n");
            for (unsigned int j = 0; j < debug_link_size; ++j) {
                printf("%c", bytes[debug_link_offset + j]);
            }
            printf("\n");
        }
        else if(strcmp(section_name, ".dynsym") == 0){
            Elf64_Shdr* dynsym_section = &section_headers[i];
            unsigned int dynstr_index = dynsym_section->sh_link; // Index of string table for dynsym

            Elf64_Sym* pElf64_Sym = (Elf64_Sym*)(bytes + dynsym_section->sh_offset);
            const char* dynstr_table = bytes + section_headers[dynstr_index].sh_offset;

            printf("Dynamic Symbols:\n");
            for (int j = 0; j < dynsym_section->sh_size / sizeof(Elf64_Sym); ++j) {
                const char* dynamic_symbol = dynstr_table + pElf64_Sym[j].st_name;
                //WIP dyn_symbol[j] = dynstr_table + pElf64_Sym[j].st_name;
                printf("%s\n", dynamic_symbol);
            }
        }
        /*else if(strcmp(section_name, ".rodata") == 0){
            unsigned int rodata_offset = section_headers[i].sh_offset;
            unsigned int rodata_size = section_headers[i].sh_size;

            // Print the bytes of .gnu_debuglink section
            printf("Contents of .gnu_debuglink section:\n");
            for (unsigned int j = 0; j < rodata_size; ++j) {
                printf("%c", bytes[rodata_offset + j]);
            }
            printf("\n");
        }*/
    }
}

int main(){
    print_sections_with_rva(read_file_bytes("./bedrock_server"));
    //print_file_bytes("./bedrock_server_symbols.debug");
    return 0;
}