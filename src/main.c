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
#include <ctype.h>
#include <stdbool.h>
#include <getopt.h>

#include "include/common.h"
#include "include/pe_tools.h"
#include "include/pe.h"

// Options of dump2exe
typedef struct {
	bool dump;
    unsigned long long offset;
} options_t;

// Simply display usage
static void usage(void)
{
	iprint("Usage: dump2exe OPTIONS FILE\n"
		"Extract PE files from memory dumps\n"
		"\nExample: dump2exe mem.dmp\n"
		"\nOptions:\n"
		" -e, --extract                             Dump the detected files.\n"
        " -o, --offset                              Dump and read at provided offset.\n"    
    );
}

// Parse the options provided by the user
static options_t *parse_options(int argc, char *argv[])
{
	options_t *options = calloc(1, sizeof(options_t));

	static const char short_options[] = "eo:";

    options->offset = 0;

	static struct option long_options[] = {
		{ "help",           no_argument,       NULL,  1  },       // Display the help
		{ "extract",        no_argument,       NULL, 'e' },       // Dump the encountered binaries
        { "offset",         required_argument, NULL, 'o' },       // Dunp only the selected ofset
		{  NULL,            0,                 NULL,  0  }
	};

	int c, ind;
    char * pEnd;

	while ((c = getopt_long(argc, argv, short_options, long_options, &ind)))
	{
		if (c < 0)
			break;

		switch (c)
		{
			case 1: 
				usage();
				exit(EXIT_SUCCESS);
			case 'e':
				options->dump = true;
				break;
            case 'o':
                
                options->offset = strtoull(optarg, &pEnd, 10);
                break;
			default:
				eprint("dump2exe: try '--help' for more information\n");
				exit(EXIT_FAILURE);
		}
	}

	return options;

}

// Main function, parses the input image and search for MZ DOS header followed by PE header 
// The function applies multiple structures to extract PE information
int parse(options_t *options,  char * file)
{

    FILE *finput = NULL;
    long fpos = 0;
    void * ptr = NULL;

    char buf[256]; 
    char buffer[4096]; 
    char mz_magic[] = {0x4D, 0x5A} ;
    
    size_t nread = 0;
    size_t tread = 0;
    size_t pr_size = 0;

    PDOS_HEADER pdos_h = NULL;
    PDOS_HEADER pdos_h_current = NULL;

    PIMAGE_NT_HEADERS64 nt_h = NULL;
    PIMAGE_NT_HEADERS64 pnt_h64_current = NULL;
    PIMAGE_NT_HEADERS32 pnt_h32_current = NULL;

    PIMAGE_OPTIONAL_HEADER64 pioh64 = NULL;

    PIMAGE_OPTIONAL_HEADER32 pioh32 = NULL;

    // Open the provided file for reading 
    finput = fopen( file, "rb");
    
    if (VALID_PTR(finput)) 
    {

        // Read chunck of the file - by default 4096
        while ( (tread = fread(&buffer, 1, CHUNCK_SIZE, finput)) == CHUNCK_SIZE) 
        {

            // For every byte, check if there is a match with the MZ Header 
            for ( int i = 0; i < sizeof(buffer) - sizeof(mz_magic); ++ i ) 
            {
                nt_h = NULL;
                pdos_h = NULL;
                pioh32 = NULL;
                pioh64 = NULL;
                pdos_h_current = NULL;
                pnt_h64_current = NULL;
                pnt_h32_current = NULL;
                ptr = NULL;

                if ( ! check_mz_magic(&buffer[i]) ) 
                {
                    continue;
                }

                // MZ header found, apply the PDOS header and search for the PE header
                pdos_h = (PDOS_HEADER) &buffer[i];
                if ( !check_pe_offset(pdos_h->PeHeaderOffset, i, CHUNCK_SIZE) ) 
                {
                    continue;
                }

                
                nt_h = (PIMAGE_NT_HEADERS64) (&buffer[i] + pdos_h->PeHeaderOffset);
                if ( ! check_pe_magic((char *)&(nt_h->Signature)) ) 
                {
                    continue;
                }
                
                // PE header found. Almost certainely a valid PE file. 
                // Register the position of the MZ for later use 
                fpos = ftell(finput)+i-tread;


                iprint("Found potential MZ at %#lx (%ld)\n", fpos, fpos);
                iprint("\tPE header offset : \t\t%#x - Valid PE signature\n", pdos_h->PeHeaderOffset);

                // Retrieve information from the Machine field in FileHeader 
                check_pe_machine(nt_h->FileHeader.Machine);

                if (nt_h->FileHeader.NumberOfSections  > 96) 
                {
                    eprint("Invalid section numbers : %#x", nt_h->FileHeader.NumberOfSections);
                    continue;
                }

                iprint("\tSection numbers : \t\t%d\n", nt_h->FileHeader.NumberOfSections);
                
                // Compute the datetime from the timestamp (seconds since 1970)
                struct tm  ts;
                ts = *localtime( (const time_t *)&(nt_h->FileHeader.TimeDateStamp) );
                strftime(buf, sizeof(buf), "%a %Y-%m-%d %H:%M:%S %Z", &ts);
                iprint("\tCompilation date : \t\t%s\n", buf);

                // Retrieve the symbole table pointer if exists
                check_symbols(nt_h->FileHeader.PointerToSymbolTable);

                // A switch is needed, depending on x64 or x86, based on the size of the header
                if (nt_h->FileHeader.SizeOfOptionalHeader == sizeof(IMAGE_OPTIONAL_HEADER32)) 
                {
                    
                    // Verify if the optional header magic matches x86
                    if (IS_SUCCESS(check_optional_headers32( (char *) &nt_h->OptionalHeader)))
                    {
                    
                        pioh32 = (PIMAGE_OPTIONAL_HEADER32) &(nt_h->OptionalHeader);
                        
                        iprint("\tImage size: \t\t\t%d bytes\n", pioh32->SizeOfImage);
                        iprint("\tSection aligments: \t\t%d bytes\n",pioh32->SectionAlignment);
                        iprint("\tFile aligment: \t\t%d bytes\n",pioh32->FileAlignment);
                        iprint("\tEntry point: \t\t\t%#x\n", pioh32->AddressOfEntryPoint);

                        // Retrieve the image base offset
                        check_imagebase((uint)pioh32->ImageBase);

                        // Pretty sure the image is valid, allocate memory to read entirely, 
                        // as the inital buffer could have cut the executable
                        ptr = malloc(pioh32->SizeOfImage);

                        if (VALID_PTR(ptr)) 
                        {

                            // Seek back to the image start
                            fseek(finput, fpos, SEEK_SET);

                            // Read the executable from the file
                            nread = fread(ptr, pioh32->SizeOfImage, 1, finput );

                            
                            if (nread < pioh32->SizeOfImage) 
                            {
                                dprint("\tSizeOfImage larger than what's readable.\n\tMaybe sections' virtual size are larger than raw size\n");
                                dprint("\tUsing read size as base.\n");
                                pr_size = nread;
                            } else {
                                pr_size = pioh32->SizeOfImage;
                            }

                            // Appliy again the PE structures on the loaded images
                            pdos_h_current = ptr;
                            pnt_h32_current = ptr + pdos_h_current->PeHeaderOffset;
                            
                            // Retrieve the characteristics of the PE 
                            check_characteristics(pnt_h32_current->FileHeader.Characteristics);

                            // Compute the MD5 of the loaded PE
                            md5_hash_from_stream(ptr, pr_size);
                            
                            // Retrieve information on the sections
                            check_sections32(pnt_h32_current, nt_h->FileHeader.NumberOfSections );

                            if (options->dump) 
                            {
                                if ( (options->offset == 0) || (options->offset != 0 && options->offset == fpos))
                                {
                                    // User wants us to dump the exe 
                                    dump_binary(ptr, pr_size, fpos, IMAGE_FILE_DLL & pnt_h32_current->FileHeader.Characteristics);
                                    iprint("\tExecutable was dumped successfully\n\n");
                                }
                            }

                            free(ptr);
                            ptr = NULL;

                            // Seek back to initial reading
                            fseek(finput, fpos+tread, SEEK_SET);

                        }
                        else 
                        {
                            eprint("Unable to allocate memory for PE. Skipping.\n");
                        }
                        
                    }
                    else 
                    {
                        eprint("Error - Skipping\n");
                    }
                
                } 
                else if (nt_h->FileHeader.SizeOfOptionalHeader == sizeof(IMAGE_OPTIONAL_HEADER64)) 
                {

                    // Verify if the optional header magic matches x64
                    if (IS_SUCCESS(check_optional_headers64( (char *) &nt_h->OptionalHeader)))
                    {
                        
                        // Get a pointer to the functionnal header 
                        pioh64 = (PIMAGE_OPTIONAL_HEADER64) &(nt_h->OptionalHeader);
                        
                        iprint("\tImage size: \t\t\t%d bytes\n", pioh64->SizeOfImage);
                        iprint("\tSection aligments: \t\t%d bytes\n",pioh64->SectionAlignment);
                        iprint("\tFile aligments: \t\t%d bytes\n",pioh64->FileAlignment);
                        iprint("\tEntry point: \t\t\t%#x\n", pioh64->AddressOfEntryPoint);

                        // Retrieve the image base offset
                        check_imagebase((uint)pioh64->ImageBase);

                        // Pretty sure the image is valid, allocate memory to read entirely, 
                        // as the inital buffer could have cut the executable
                        ptr = malloc((size_t)pioh64->SizeOfImage);

                        dprint("\n\tAllocated %d for image\n", pioh64->SizeOfImage);
                        if (VALID_PTR(ptr)) 
                        {

                            // Seek back to the image start
                            fseek(finput, fpos, SEEK_SET);
                            dprint("\tSeeked to %#lx to read image\n", ftell(finput));

                            // Read the executable from the file
                            nread = fread(ptr, 1, (size_t)pioh64->SizeOfImage, finput );

                            dprint("\tRead %ld of file\n", nread);

                            if (nread < pioh64->SizeOfImage) 
                            {
                                dprint("\tSizeOfImage larger than what's readable.\n\tMaybe sections' virtual size are larger than raw size\n");
                                dprint("\tUsing read size as base.\n");
                                pr_size = nread;
                            } else {
                                pr_size = pioh64->SizeOfImage;
                            }

                            // Apply aggain the PE structures on the loaded images
                            dprint("\tPointer of loaded image : %p\n", (void *)ptr);
                            pdos_h_current = (PDOS_HEADER)((char *)ptr);
                            
                            dprint("\tPointer of PDOS header %p\n", (void *)pdos_h_current);
                            if (check_mz_magic((char *)pdos_h_current)) 
                            {
                                dprint("\tLoaded DOS Magic %#x\n", pdos_h_current->DosMagic);
                                dprint("\tLoaded PE Offset %d\n", pdos_h_current->PeHeaderOffset);
                                pnt_h64_current = (PIMAGE_NT_HEADERS64)((char *)ptr + pdos_h_current->PeHeaderOffset);
                                
                                // Retrieve the characteristics of the PE 
                                dprint("\tLoaded PE Magic %#x\n", pnt_h64_current->Signature);
                                check_characteristics(pnt_h64_current->FileHeader.Characteristics);

                                // Compute the MD5 of the loaded PE
                                md5_hash_from_stream(ptr, pr_size);
                                
                                // Retrieve information on the sections
                                check_sections64(pnt_h64_current, nt_h->FileHeader.NumberOfSections);

                                if (options->dump) 
                                {
                                    if ( (options->offset == 0) || (options->offset != 0 && options->offset == fpos))
                                    {
                                        // User wants us to dump the exe 
                                        dump_binary(ptr, pr_size, fpos, IMAGE_FILE_DLL & pnt_h64_current->FileHeader.Characteristics);
                                        iprint("\tExecutable was dumped successfully\n\n");
                                    }
                                }
                            }
                            else 
                            {
                                eprint("Prevented error on reading.");
                            }

                            free(ptr);
                            ptr = NULL;

                            // Seek back to initial reading
                            fseek(finput, fpos+tread, SEEK_SET);

                        }
                        else 
                        {
                            eprint("Unable to allocate memory for PE. Skipping.\n");
                        }
                    }
                    else 
                    {
                        eprint("Error - skipping\n");
                    }

                }

                iprint("\n"); 
                    
            }
        }
        
        iprint("\n"); 

        fclose(finput);
    }
    else 
    {
        eprint("Unable to open file\n");
    }

    return RET_SUCCESS;
}


int main(int argc, char ** argv) {

    options_t *options = parse_options(argc, argv);

    parse(options, argv[argc-1]);

    free(options);

}