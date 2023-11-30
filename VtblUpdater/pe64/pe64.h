
#include <stdint.h>

typedef unsigned short WORD; //i dont like this
typedef unsigned int   DWORD;

typedef struct _IMAGE_FILE_HEADER {
    unsigned short Machine;             // Architecture type
    unsigned short NumberOfSections;    // Number of sections
    unsigned long TimeDateStamp;        // Time and date of creation
    unsigned long PointerToSymbolTable; // File offset of the COFF symbol table
    unsigned long NumberOfSymbols;      // Number of symbols in the COFF symbol table
    unsigned short SizeOfOptionalHeader; // Size of the optional header
    unsigned short Characteristics;     // File characteristics
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DOS_HEADER {
    unsigned short e_magic;    // Magic number (MZ)
    unsigned short e_cblp;
    unsigned short e_cp;
    unsigned short e_crlc;
    unsigned short e_cparhdr;
    unsigned short e_minalloc;
    unsigned short e_maxalloc;
    unsigned short e_ss;
    unsigned short e_sp;
    unsigned short e_csum;
    unsigned short e_ip;
    unsigned short e_cs;
    unsigned short e_lfarlc;
    unsigned short e_ovno;
    unsigned short e_res[4];
    unsigned short e_oemid;
    unsigned short e_oeminfo;
    unsigned short e_res2[10];
    long e_lfanew;             // File address of the PE header
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    unsigned long VirtualAddress;
    unsigned long Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    unsigned short Magic;                     // Magic number
    unsigned char  MajorLinkerVersion;
    unsigned char  MinorLinkerVersion;
    unsigned long  SizeOfCode;
    unsigned long  SizeOfInitializedData;
    unsigned long  SizeOfUninitializedData;
    unsigned long  AddressOfEntryPoint;
    unsigned long  BaseOfCode;
    unsigned long long ImageBase;             // Preferred base address
    unsigned long  SectionAlignment;
    unsigned long  FileAlignment;
    unsigned short MajorOperatingSystemVersion;
    unsigned short MinorOperatingSystemVersion;
    unsigned short MajorImageVersion;
    unsigned short MinorImageVersion;
    unsigned short MajorSubsystemVersion;
    unsigned short MinorSubsystemVersion;
    unsigned long  Win32VersionValue;
    unsigned long  SizeOfImage;
    unsigned long  SizeOfHeaders;
    unsigned long  CheckSum;
    unsigned short Subsystem;
    unsigned short DllCharacteristics;
    unsigned long long SizeOfStackReserve;
    unsigned long long SizeOfStackCommit;
    unsigned long long SizeOfHeapReserve;
    unsigned long long SizeOfHeapCommit;
    unsigned long  LoaderFlags;
    unsigned long  NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];  // Array of data directories
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_SECTION_HEADER {
    unsigned char Name[8];         // Section name
    unsigned long VirtualSize;      // Virtual size of section
    unsigned long VirtualAddress;   // Virtual address of section
    unsigned long SizeOfRawData;    // Size of raw data in the section
    unsigned long PointerToRawData; // File pointer to raw data
    unsigned long PointerToRelocations;   // File pointer to relocation table
    unsigned long PointerToLinenumbers;   // File pointer to line numbers
    unsigned short NumberOfRelocations;   // Number of relocations
    unsigned short NumberOfLinenumbers;   // Number of line numbers
    unsigned long Characteristics; // Section characteristics
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef struct _IMAGE_NT_HEADERS64{
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;