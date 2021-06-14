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

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h> 
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdbool.h>
#include <openssl/md5.h>

#include "include/pe.h"
#include "include/common.h"

void section_characteristics(uint32_t characteristics) 
{
    static const SECTIONS_CHARACTERISTICS names[] = {
		{ IMAGE_SCN_TYPE_NO_PAD, 				"IMAGE_SCN_TYPE_NO_PAD" },
		{ IMAGE_SCN_CNT_CODE, 					"Contains code" },
		{ IMAGE_SCN_CNT_INITIALIZED_DATA,       "Initialized data" },
		{ IMAGE_SCN_CNT_UNINITIALIZED_DATA,     "Uninitialized data" },
		{ IMAGE_SCN_LNK_OTHER, 					"IMAGE_SCN_LNK_OTHER" },
		{ IMAGE_SCN_LNK_INFO, 					"Info" },
		{ IMAGE_SCN_LNK_REMOVE, 				"Unlinked" },
		{ IMAGE_SCN_LNK_COMDAT, 				"Contains COMDAT" },
		{ IMAGE_SCN_NO_DEFER_SPEC_EXC,          "IMAGE_SCN_NO_DEFER_SPEC_EXC" },
		{ IMAGE_SCN_GPREL, 					    "IMAGE_SCN_GPREL" },
		{ IMAGE_SCN_MEM_PURGEABLE, 				"IMAGE_SCN_MEM_PURGEABLE" },
		{ IMAGE_SCN_MEM_LOCKED, 				"IMAGE_SCN_MEM_LOCKED" },
		{ IMAGE_SCN_MEM_PRELOAD, 				"IMAGE_SCN_MEM_PRELOAD" },
		{ IMAGE_SCN_ALIGN_1BYTES, 				"IMAGE_SCN_ALIGN_1BYTES" },
		{ IMAGE_SCN_ALIGN_2BYTES, 				"IMAGE_SCN_ALIGN_2BYTES" },
		{ IMAGE_SCN_ALIGN_4BYTES, 				"IMAGE_SCN_ALIGN_4BYTES" },
		{ IMAGE_SCN_ALIGN_8BYTES, 				"IMAGE_SCN_ALIGN_8BYTES" },
		{ IMAGE_SCN_ALIGN_16BYTES, 				"IMAGE_SCN_ALIGN_16BYTES" },
		{ IMAGE_SCN_ALIGN_32BYTES, 				"IMAGE_SCN_ALIGN_32BYTES" },
		{ IMAGE_SCN_ALIGN_64BYTES, 				"IMAGE_SCN_ALIGN_64BYTES" },
		{ IMAGE_SCN_ALIGN_128BYTES, 			"IMAGE_SCN_ALIGN_128BYTES" },
		{ IMAGE_SCN_ALIGN_256BYTES, 			"IMAGE_SCN_ALIGN_256BYTES" },
		{ IMAGE_SCN_ALIGN_512BYTES, 			"IMAGE_SCN_ALIGN_512BYTES" },
		{ IMAGE_SCN_ALIGN_1024BYTES, 			"IMAGE_SCN_ALIGN_1024BYTES" },
		{ IMAGE_SCN_ALIGN_2048BYTES, 			"IMAGE_SCN_ALIGN_2048BYTES" },
		{ IMAGE_SCN_ALIGN_4096BYTES, 			"IMAGE_SCN_ALIGN_4096BYTES" },
		{ IMAGE_SCN_ALIGN_8192BYTES, 			"IMAGE_SCN_ALIGN_8192BYTES" },
		{ IMAGE_SCN_LNK_NRELOC_OVFL, 			"Extended relocation" },
		{ IMAGE_SCN_MEM_DISCARDABLE, 			"IMAGE_SCN_MEM_DISCARDABLE" },
		{ IMAGE_SCN_MEM_NOT_CACHED, 			"Cannot be cached" },
		{ IMAGE_SCN_MEM_NOT_PAGED, 				"Cannot be paged" },
		{ IMAGE_SCN_MEM_SHARED, 				"Can be shared" },
		{ IMAGE_SCN_MEM_EXECUTE, 				"Can be exec" },
		{ IMAGE_SCN_MEM_READ, 					"Can be read" },
		{ IMAGE_SCN_MEM_WRITE,                  "Can be write"}
	};

    printf("\tCharacteristics : ");
    for (uint32_t i=0; i < 35; i++) {
        if ((names[i].FlagValue & characteristics) == names[i].FlagValue) {
            iprint("%.60s - ", names[i].FlagName);
        }
    }
}

void check_sections64(PIMAGE_NT_HEADERS64 nt_h, DWORD wValidation) 
{
    PIMAGE_SECTION_HEADER tmpSection = NULL;
    void * sections_ptr = NULL;
    uint sections_offset = sizeof(nt_h->Signature) 
                            + sizeof(IMAGE_FILE_HEADER) 
                            + nt_h->FileHeader.SizeOfOptionalHeader;

    sections_ptr = (void *)((char *)nt_h + sections_offset);

    if (wValidation != nt_h->FileHeader.NumberOfSections) {
        eprint("\tMisreading. Using pre-read sections value");
    }

    printf("\tSections : \n");
    
    for (uint i = 0; i < wValidation; i++) 
    {
        tmpSection = sections_ptr + i * sizeof(IMAGE_SECTION_HEADER);
        iprint("\t\t\t\t\t%.8s:\t\t", tmpSection->Name);
        section_characteristics(tmpSection->Characteristics);
        iprint("\n");
    }

    iprint("\n");
}

void check_sections32(PIMAGE_NT_HEADERS32 nt_h, WORD wValidation) 
{
    PIMAGE_SECTION_HEADER tmpSection = NULL;
    void * sections_ptr = NULL;
    uint sections_offset = sizeof(nt_h->Signature) 
                            + sizeof(IMAGE_FILE_HEADER) 
                            + nt_h->FileHeader.SizeOfOptionalHeader;

    sections_ptr = (void *)((char *)nt_h + sections_offset);

    if (wValidation != nt_h->FileHeader.NumberOfSections) {
        eprint("\tMisreading. Using pre-read sections value");
    }

    iprint("\tSections : \n");
    
    for (uint i = 0; i < wValidation; i++) 
    {
        tmpSection = sections_ptr + i * sizeof(IMAGE_SECTION_HEADER);
        iprint("\t\t\t\t\t%.8s:\t\t", tmpSection->Name);
        section_characteristics(tmpSection->Characteristics);
        iprint("\n");
    }

    iprint("\n");
}



void check_characteristics( WORD characteristics ) 
{
    	static const IMG_CHARACTERISTICS characteristicsTable[] = {
		{ IMAGE_FILE_RELOCS_STRIPPED,			"base relocations stripped"					},
		{ IMAGE_FILE_EXECUTABLE_IMAGE,			"executable image"							},
		{ IMAGE_FILE_LINE_NUMS_STRIPPED,		"line numbers removed"			            },
		{ IMAGE_FILE_LOCAL_SYMS_STRIPPED,		"local symbols removed"		                },
		{ IMAGE_FILE_AGGRESSIVE_WS_TRIM,		"aggressively trim"                         },
		{ IMAGE_FILE_LARGE_ADDRESS_AWARE,		"large address aware"		                },
		{ IMAGE_FILE_RESERVED,					"reserved"								    },
		{ IMAGE_FILE_BYTES_REVERSED_LO,			"little-endian"             				},
		{ IMAGE_FILE_32BIT_MACHINE,				"32-bit machine"							},
		{ IMAGE_FILE_DEBUG_STRIPPED,			"debug info removed"				        },
		{ IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP,	"swap if on removable media"	            },
		{ IMAGE_FILE_NET_RUN_FROM_SWAP,			"swap if on network media"		            },
		{ IMAGE_FILE_SYSTEM,					"system file"								},
		{ IMAGE_FILE_DLL,						"DLL image"									},
		{ IMAGE_FILE_UP_SYSTEM_ONLY,			"uniprocessor machine"						},
		{ IMAGE_FILE_BYTES_REVERSED_HI,			"big-endian (deprecated)"					}
	};

    printf("\tCharacteristics: \t\t");
    for (uint16_t i=0; i < 16; i++) {
        if ((characteristics & characteristicsTable[i].FlagValue) == characteristicsTable[i].FlagValue) {
            printf("%s, ", characteristicsTable[i].FlagName);
        }
    }
    printf("\n");
}

void md5_hash_from_stream (char *buffer, size_t buffer_size)
{
    unsigned char result[MD5_DIGEST_LENGTH];
    MD5((unsigned char*) buffer, buffer_size, result);

    char md5string[33];
    for(int i = 0; i < 16; ++i)
        sprintf(&md5string[i*2], "%02X", (unsigned int)result[i]);

    iprint("\tMD5 : \t\t\t\t%s\n", md5string);
}


int dump_binary(void * ptr, DWORD size_of_image, long image_offset, bool is_dll) 
{
    
    char foutput_name[60];
    FILE * foutput = NULL;
    struct stat st = {0};

    if (stat("__bin_extracted/", &st) == -1) {
        mkdir("__bin_extracted/", 0700);
    }

    if (is_dll) 
    {
        sprintf(foutput_name, "__bin_extracted/bin_%#lx.dll",image_offset);
    } 
    else 
    {
        sprintf(foutput_name, "__bin_extracted/bin_%#lx.exe",image_offset);
    }
    
    foutput = fopen(foutput_name, "w");
    fwrite(ptr, size_of_image, 1, foutput);

    fclose(foutput);

    return RET_SUCCESS;
}   

int check_imagebase(uint image_base) 
{

    if (image_base == 0x10000000) {

        iprint("\tImage base : \t\t\tmatches DLL\n");

    }
    else if (image_base == 0x00400000) {

        iprint("\tImage base : \t\t\tmatches EXE\n");

    }
    else if (image_base == 0x00010000) {

        iprint("\tImage base : \t\t\tmatches CE app\n");

    }
    else {
        
        iprint("\tImage base : \t\t\t%#x\n", image_base);

    }
    return RET_SUCCESS;
}

int check_optional_headers32(char * ptr_oh) 
{

    PIMAGE_OPTIONAL_HEADER32 pioh32 = NULL;
    pioh32 = (PIMAGE_OPTIONAL_HEADER32)ptr_oh;
    if (pioh32->Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        
        iprint("\tOptional header magic: \t\tx86\n");

        return RET_SUCCESS;
    }
    else 
    {
        iprint("\tOptional header magic: \t\tERROR ! Expected x86 - Got %x#\n", pioh32->Magic);
        return RET_ERROR;
    }
    
}

int check_optional_headers64(char * ptr_oh) 
{
    
    PIMAGE_OPTIONAL_HEADER64 pioh64 = NULL;

    pioh64 = (PIMAGE_OPTIONAL_HEADER64)ptr_oh;
        
    if (pioh64->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {

        iprint("\tOptional header magic: \t\tx64\n");
        return RET_SUCCESS;

    }
    
    return RET_ERROR;
}

int check_symbols(DWORD symbol_offset) 
{

    if (symbol_offset != 0) {
    
        iprint("\tSymbol: \t\t\tOffset at %#x\n", symbol_offset);
        return RET_SUCCESS;
    }

    iprint("\tSymbol: \t\t\tNo symbol table\n");
    return RET_ERROR;
}

int check_pe_offset(uint pe_offset, uint round, uint boundery) 
{

    if ( 0x0 < pe_offset  && pe_offset < 0xFFFF && (pe_offset+round) < boundery) {
        return RET_SUCCESS;
    } 

    return RET_ERROR;
}

int check_mz_magic(char * ptr_buffer) 
{

    char mz_magic[] = {0x4D, 0x5A} ;
    
    if ( memcmp(ptr_buffer, mz_magic, sizeof(mz_magic)) == 0 ) {
        return RET_SUCCESS;
    } 

    return RET_ERROR;

}

int check_pe_magic(char * ptr_buffer) 
{

     char pe_magic[] = {0x50, 0x45, 0x00, 0x00} ;
    
    if ( memcmp(ptr_buffer, pe_magic, sizeof(pe_magic)) == 0 ) {
        return RET_SUCCESS;
    } 
    return RET_ERROR;
}

int check_pe_machine(WORD pe_machine) 
{

    if ( pe_machine == IMAGE_FILE_MACHINE_AMD64) {
        iprint("\tMachine: \t\t\tx64 binary detected\n");
        return IMAGE_FILE_MACHINE_AMD64;
    }
    else if ( pe_machine == IMAGE_FILE_MACHINE_I386) {
        iprint("\tMachine: \t\t\tx86 binary detected\n");
        return IMAGE_FILE_MACHINE_I386;
    }
    else if ( pe_machine == IMAGE_FILE_MACHINE_IA64 ) {
        iprint("\tMachine: \t\t\tItanium binary detected - NOT SUPPORTED\n");
        return RET_ERROR;
    }

    iprint("\tMachine: \t\t\tUnsupported %#x\n", pe_machine);
    return RET_ERROR;
}

time_t GetTimeAndDate(unsigned long long milliseconds)
{
    time_t seconds = (time_t)(milliseconds/1000);
    if ((unsigned long long)seconds*1000 == milliseconds)
        return seconds;
    return (time_t)NULL; // milliseconds >= 4G*1000
}