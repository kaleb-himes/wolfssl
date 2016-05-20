
/* wolfcrypt/benchmark/wc_stack_profiler.h
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */


#ifndef WOLFCRYPT_MEASURE_STACK_H
#define WOLFCRYPT_MEASURE_STACK_H

#ifdef __cplusplus
    extern "C" {
#endif

#include <stddef.h>

/* define this to be the actual size of the stack you are using 
 * then comment out the line below this comment with #error */
//#error  WOLFSSL_STACK_SIZE must be set before proceeding
#define WOLFSSL_STACK_SIZE 8192

size_t wolfStackPointer = 0;
size_t wolfFuncOverhead = 0;

void wc_StackBegin(void);
size_t wc_GetStackPosition(void);
void wc_CalcFuncOverhead(size_t begin);
size_t wc_CalcStackUsage(size_t startP, size_t endP);
int stack_profile_test(void *args);
#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFCRYPT_MEASURE_STACK_H */
