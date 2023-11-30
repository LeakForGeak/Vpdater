
#include "../pe64/pe64.h"

int rva2foa(PIMAGE_DOS_HEADER pImageDosHeader, DWORD dwtargetRVA){
    int target_foa = -1;
    PIMAGE_NT_HEADERS64 pImageNtHeader64 = (PIMAGE_NT_HEADERS64)(pImageDosHeader + pImageDosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER pImageSectionHeader = (PIMAGE_SECTION_HEADER)(pImageNtHeader64 + sizeof(IMAGE_NT_HEADERS64));

    for(int i = 0; i < pImageNtHeader64->FileHeader.NumberOfSections; i++){
        if((dwtargetRVA >= pImageSectionHeader->VirtualAddress) && (dwtargetRVA <= (pImageSectionHeader->VirtualAddress + pImageSectionHeader->SizeOfRawData)))
        {
            target_foa = dwtargetRVA - pImageSectionHeader->VirtualAddress;
            target_foa = pImageSectionHeader->PointerToRawData;
        }

        pImageSectionHeader++;
    }
    return target_foa;
}

const char* get_section_name_via_rva(PIMAGE_DOS_HEADER pImageDosHeader, DWORD dwRva){
    const char* section_name = 0;

    PIMAGE_NT_HEADERS64 pImageNtHeader64 = (PIMAGE_NT_HEADERS64)(pImageDosHeader + pImageDosHeader->e_lfanew);

    PIMAGE_SECTION_HEADER pImageSectionHeader = (PIMAGE_SECTION_HEADER)(pImageNtHeader64 + sizeof(IMAGE_NT_HEADERS64));
    for(int i = 0;i < pImageNtHeader64->FileHeader.NumberOfSections; i++){
        if((dwRva >= pImageSectionHeader->VirtualAddress) && (dwRva <= (pImageSectionHeader->VirtualAddress + pImageSectionHeader->SizeOfRawData))){
            section_name = pImageSectionHeader->Name;
        }
        pImageSectionHeader++;
    }
    return section_name;
}

void dump_section_names(PIMAGE_DOS_HEADER pImageDosHeader) {
    PIMAGE_NT_HEADERS64 pImageNtHeader64 = (PIMAGE_NT_HEADERS64)((DWORD_PTR)pImageDosHeader + pImageDosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER pImageSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)pImageNtHeader64 + sizeof(IMAGE_NT_HEADERS64));

    printf("Section Names:\n");
    for (int i = 0; i < pImageNtHeader64->FileHeader.NumberOfSections; i++) {
        printf("%.*s\n", IMAGE_SIZEOF_SHORT_NAME, pImageSectionHeader->Name);
        pImageSectionHeader++;
    }
}