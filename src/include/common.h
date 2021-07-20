/*
 *  dump2exe - Dump PE extractor 
 * 
 * "THE BEER-WARE LICENSE" (Revision 42):
 * whitekernel - PAM wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.  
 */

#pragma once 

#define CHUNCK_SIZE     4096
#define RET_SUCCESS     1
#define RET_ERROR       0
#define DEBUG           0

#define no_argument         0
#define required_argument   1


#define VALID_PTR(_ptr)     (_ptr != NULL)
#define IS_SUCCESS(_ret)    (_ret > 0)
#define IS_FAILURE(_ret)    !IS_SUCCESS(_ret)

#define iprint(_msg, ...)       fprintf(stdout, (const char *)_msg __VA_OPT__(,) __VA_ARGS__)
#define eprint(_msg, ...)       fprintf(stderr, (const char *)_msg __VA_OPT__(,) __VA_ARGS__)
#define dprint(_msg, ...)       if (DEBUG) { fprintf(stderr, (const char *)_msg __VA_OPT__(,) __VA_ARGS__); }