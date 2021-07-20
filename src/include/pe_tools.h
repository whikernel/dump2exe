/*
 *  dump2exe - Dump PE extractor 
 * 
 * "THE BEER-WARE LICENSE" (Revision 42):
 * whitekernel - PAM wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.  
 */

#pragma once 

#include <time.h>

#include "common.h"
#include "pe.h"

time_t GetTimeAndDate(unsigned long long milliseconds);
int dump_binary(void * ptr, DWORD size_of_image, long image_offset, bool is_dll);
int check_imagebase(uint image_base);
int check_optional_headers32(char * ptr_oh);
int check_optional_headers64(char * ptr_oh);
int check_symbols(DWORD symbol_offset);
int check_pe_offset(uint pe_offset, uint round, uint boundery) ;
int check_mz_magic(char * ptr_buffer);
int check_pe_magic(char * ptr_buffer);
int check_pe_machine(WORD pe_machine);
void md5_hash_from_stream (char *buffer, size_t buffer_size);
void check_characteristics( WORD characteristics );
void check_sections32(PIMAGE_NT_HEADERS32 nt_h, WORD dwValidation);
void check_sections64(PIMAGE_NT_HEADERS64 nt_h, WORD dwValidation);
void section_characteristics(uint32_t characteristics);