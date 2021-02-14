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

#define CHUNCK_SIZE     4096
#define RET_SUCCESS     1
#define RET_ERROR       0

#define no_argument         0
#define required_argument   1


#define VALID_PTR(_ptr)     (_ptr != NULL)
#define IS_SUCCESS(_ret)    (_ret > 0)

#define iprint(_msg, ...)       fprintf(stdout, (const char *)_msg __VA_OPT__(,) __VA_ARGS__)
#define eprint(_msg, ...)       fprintf(stderr, (const char *)_msg __VA_OPT__(,) __VA_ARGS__)