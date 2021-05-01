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