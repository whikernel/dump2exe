/*
    dump2exe - Dump PE extractor 
    whitekernel - PAM - 2020 
    
    This file is part of dump2exe.
    Under MIT License

    Copyright (c) 2021 whitekernel - PAM

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
*/

#pragma once 

#include <stdint.h>

typedef uint DWORD;
typedef unsigned short WORD;
typedef unsigned char BYTE;
typedef double ULONGLONG;

#define IMAGE_FILE_RELOCS_STRIPPED          0x0001
#define IMAGE_FILE_EXECUTABLE_IMAGE         0x0002
#define IMAGE_FILE_LINE_NUMS_STRIPPED       0x0004
#define IMAGE_FILE_LOCAL_SYMS_STRIPPED      0x0008
#define IMAGE_FILE_AGGRESSIVE_WS_TRIM       0x0010
#define IMAGE_FILE_LARGE_ADDRESS_AWARE      0x0020
#define IMAGE_FILE_RESERVED	                0x0040
#define IMAGE_FILE_BYTES_REVERSED_LO        0x0080
#define IMAGE_FILE_32BIT_MACHINE            0x0100
#define IMAGE_FILE_DEBUG_STRIPPED           0x0200
#define IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP  0x0400
#define IMAGE_FILE_NET_RUN_FROM_SWAP        0x0800
#define IMAGE_FILE_SYSTEM                   0x1000
#define IMAGE_FILE_DLL                      0x2000
#define IMAGE_FILE_UP_SYSTEM_ONLY           0x4000
#define IMAGE_FILE_BYTES_REVERSED_HI        0x8000

#define IMAGE_SCN_RESERVED_0	        0x00000001
#define IMAGE_SCN_RESERVED_1	        0x00000002
#define IMAGE_SCN_RESERVED_2	        0x00000004
#define IMAGE_SCN_TYPE_NO_PAD	        0x00000008 /* don't pad - obsolete */
#define IMAGE_SCN_RESERVED_3	        0x00000010
#define IMAGE_SCN_CNT_CODE	          0x00000020 /* .text */
#define IMAGE_SCN_CNT_INITIALIZED_DATA 0x00000040 /* .data */
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA 0x00000080 /* .bss */
#define IMAGE_SCN_LNK_OTHER	          0x00000100 /* reserved */
#define IMAGE_SCN_LNK_INFO	          0x00000200 /* .drectve comments */
#define IMAGE_SCN_RESERVED_4	        0x00000400
#define IMAGE_SCN_LNK_REMOVE	        0x00000800 /* .o only - scn to be rm'd*/
#define IMAGE_SCN_LNK_COMDAT	        0x00001000 /* .o only - COMDAT data */
#define IMAGE_SCN_RESERVED_5	        0x00002000 /* spec omits this */
#define IMAGE_SCN_RESERVED_6	        0x00004000 /* spec omits this */
#define IMAGE_SCN_GPREL		            0x00008000 /* global pointer referenced data */
/* spec lists 0x20000 twice, I suspect they meant 0x10000 for one of them */
#define IMAGE_SCN_MEM_PURGEABLE	      0x00010000 /* reserved for "future" use */
#define IMAGE_SCN_16BIT		            0x00020000 /* reserved for "future" use */
#define IMAGE_SCN_LOCKED	            0x00040000 /* reserved for "future" use */
#define IMAGE_SCN_PRELOAD	            0x00080000 /* reserved for "future" use */
/* and here they just stuck a 1-byte integer in the middle of a bitfield */
#define IMAGE_SCN_ALIGN_1BYTES	      0x00100000 /* it does what it says on the box */
#define IMAGE_SCN_ALIGN_2BYTES	      0x00200000
#define IMAGE_SCN_ALIGN_4BYTES	      0x00300000
#define IMAGE_SCN_ALIGN_8BYTES	      0x00400000
#define IMAGE_SCN_ALIGN_16BYTES	      0x00500000
#define IMAGE_SCN_ALIGN_32BYTES	      0x00600000
#define IMAGE_SCN_ALIGN_64BYTES	      0x00700000
#define IMAGE_SCN_ALIGN_128BYTES      0x00800000
#define IMAGE_SCN_ALIGN_256BYTES      0x00900000
#define IMAGE_SCN_ALIGN_512BYTES      0x00a00000
#define IMAGE_SCN_ALIGN_1024BYTES     0x00b00000
#define IMAGE_SCN_ALIGN_2048BYTES     0x00c00000
#define IMAGE_SCN_ALIGN_4096BYTES     0x00d00000
#define IMAGE_SCN_ALIGN_8192BYTES     0x00e00000
#define IMAGE_SCN_LNK_NRELOC_OVFL     0x01000000 /* extended relocations */
#define IMAGE_SCN_MEM_DISCARDABLE     0x02000000 /* scn can be discarded */
#define IMAGE_SCN_MEM_NOT_CACHED      0x04000000 /* cannot be cached */
#define IMAGE_SCN_MEM_NOT_PAGED	      0x08000000 /* not pageable */
#define IMAGE_SCN_MEM_SHARED	        0x10000000 /* can be shared */
#define IMAGE_SCN_MEM_EXECUTE	        0x20000000 /* can be executed as code */
#define IMAGE_SCN_MEM_READ	          0x40000000 /* readable */
#define IMAGE_SCN_MEM_WRITE	          0x80000000 /* writeable */
#define IMAGE_SCN_NO_DEFER_SPEC_EXC   0x00004000
#define IMAGE_SCN_MEM_LOCKED          0x00040000
#define IMAGE_SCN_MEM_PRELOAD         0x00080000

typedef struct _IMG_CHARACTERISTICS {
    WORD          FlagValue;
    char * const  FlagName;    
}IMG_CHARACTERISTICS, *PIMG_CHARACTERISTICS;

typedef struct _SECTIONS_CHARACTERISTICS {
    DWORD         FlagValue;
    char * const  FlagName;    
}SECTIONS_CHARACTERISTICS, *PSECTIONS_CHARACTERISTICS;

#define IMAGE_SIZEOF_SHORT_NAME 8
typedef struct _IMAGE_SECTION_HEADER {
  BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];
  union {
    uint32_t PhysicalAddress;
    uint32_t VirtualSize;
  } Misc;
  uint32_t VirtualAddress;
  uint32_t SizeOfRawData;
  uint32_t PointerToRawData;
  uint32_t PointerToRelocations;
  uint32_t PointerToLinenumbers;
  uint16_t NumberOfRelocations;
  uint16_t NumberOfLinenumbers;
  uint32_t Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef struct _DOS_HEADER {
    WORD    DosMagic;              // 2 bytes MZ
    WORD    Padding[29];           // 58 bytes padding
    uint    PeHeaderOffset;        // 4 bytes offset

} DOS_HEADER, *PDOS_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD VirtualAddress;
    DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD                 Magic;
    BYTE                 MajorLinkerVersion;
    BYTE                 MinorLinkerVersion;
    DWORD                SizeOfCode;
    DWORD                SizeOfInitializedData;
    DWORD                SizeOfUninitializedData;
    DWORD                AddressOfEntryPoint;
    DWORD                BaseOfCode;
    ULONGLONG            ImageBase;
    DWORD                SectionAlignment;
    DWORD                FileAlignment;
    WORD                 MajorOperatingSystemVersion;
    WORD                 MinorOperatingSystemVersion;
    WORD                 MajorImageVersion;
    WORD                 MinorImageVersion;
    WORD                 MajorSubsystemVersion;
    WORD                 MinorSubsystemVersion;
    DWORD                Win32VersionValue;
    DWORD                SizeOfImage;
    DWORD                SizeOfHeaders;
    DWORD                CheckSum;
    WORD                 Subsystem;
    WORD                 DllCharacteristics;
    ULONGLONG            SizeOfStackReserve;
    ULONGLONG            SizeOfStackCommit;
    ULONGLONG            SizeOfHeapReserve;
    ULONGLONG            SizeOfHeapCommit;
    DWORD                LoaderFlags;
    DWORD                NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_OPTIONAL_HEADER {
    WORD                 Magic;
    BYTE                 MajorLinkerVersion;
    BYTE                 MinorLinkerVersion;
    DWORD                SizeOfCode;
    DWORD                SizeOfInitializedData;
    DWORD                SizeOfUninitializedData;
    DWORD                AddressOfEntryPoint;
    DWORD                BaseOfCode;
    DWORD                BaseOfData;
    DWORD                ImageBase;
    DWORD                SectionAlignment;
    DWORD                FileAlignment;
    WORD                 MajorOperatingSystemVersion;
    WORD                 MinorOperatingSystemVersion;
    WORD                 MajorImageVersion;
    WORD                 MinorImageVersion;
    WORD                 MajorSubsystemVersion;
    WORD                 MinorSubsystemVersion;
    DWORD                Win32VersionValue;
    DWORD                SizeOfImage;
    DWORD                SizeOfHeaders;
    DWORD                CheckSum;
    WORD                 Subsystem;
    WORD                 DllCharacteristics;
    DWORD                SizeOfStackReserve;
    DWORD                SizeOfStackCommit;
    DWORD                SizeOfHeapReserve;
    DWORD                SizeOfHeapCommit;
    DWORD                LoaderFlags;
    DWORD                NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_FILE_HEADER {
  WORD  Machine;
  WORD  NumberOfSections;
  DWORD TimeDateStamp;      
  DWORD PointerToSymbolTable;
  DWORD NumberOfSymbols;
  WORD  SizeOfOptionalHeader;
  WORD  Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;


typedef struct _IMAGE_NT_HEADERS32 {
  int                       Signature;
  IMAGE_FILE_HEADER         FileHeader;
  IMAGE_OPTIONAL_HEADER32   OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

typedef struct _IMAGE_NT_HEADERS64 {
  int                       Signature;
  IMAGE_FILE_HEADER         FileHeader;
  IMAGE_OPTIONAL_HEADER64   OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;


#define IMAGE_FILE_MACHINE_I386         0x14c
#define IMAGE_FILE_MACHINE_IA64         0x0200
#define IMAGE_FILE_MACHINE_AMD64        0x8664

#define IMAGE_NT_OPTIONAL_HDR32_MAGIC 0x10b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20b