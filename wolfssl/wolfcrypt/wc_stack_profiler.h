
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


#ifndef WOLFCRYPT_STACK_PROFILER_H
#define WOLFCRYPT_STACK_PROFILER_H

#ifdef __cplusplus
 extern "C" {
#endif

    #ifdef HAVE_CONFIG_H
        #include <config.h>
    #endif
    #include <wolfssl/wolfcrypt/settings.h>
    #include <stddef.h>
    #include <stdio.h>


    /* define this to be the actual size of the stack you are using 
     * then comment out the line below this comment with #error */
    //#error  WOLFSSL_STACK_SIZE must be set before proceeding
    #define WOLFSSL_STACK_SIZE 8192

    static size_t wolfStackPointer = 0;
    static size_t wolfFuncOverhead = 0;
    static size_t stackBytesUsed   = 0;
    /* Supports a single call-depth measurement of the stack. To support
     * variable call-depths we will need to track these usages over time
     */

    static inline size_t wc_CalcStackUsage(size_t startP, size_t endP)
    {
        size_t ret, tempRet;
        /* If stack fill direction is top to bottom (back to front) value will be
         * a large negative with start - end as size_t is unsigned
         * if this happens use end - start instead. */
        ret = startP - endP;
        if (ret > WOLFSSL_STACK_SIZE) {
            tempRet = ret;
            ret = endP - startP;
        }
        if (ret > WOLFSSL_STACK_SIZE) {
            printf("\nCAUTION: Stack overflow detected verify"
                    " WOLFSSL_STACK_SIZE\n");
            printf("Checking both fill directions on stack\n");
            if (tempRet < ret) {
                printf("tempRet = %lu\n", tempRet);
                printf("ret =     %lu\n", ret);
                ret = tempRet;
            }
        }
        /* Try to account for overhead on systems where simply creating a function
         * has an overhead cost assosciated with it. (FreeRTOS is one example)
         */
        ret = ret - wolfFuncOverhead;

        /* Deciding if there is a need to detect "Alignment" IE
         * Problem: If there is stack consumption because of "Alignment" should
         *          that be accounted for or included in the calculation as it
         *          is associated with the cost of the algorithm.
         */

        return ret;
    }

    static inline size_t wc_GetStackPosition() {
        size_t* currStackPointer = NULL;
        size_t ret;
        ret = (size_t) &currStackPointer;
        return ret;
    }

    static inline void wc_CalcFuncOverhead() {
        size_t end = wc_GetStackPosition();
        printf("wolfStackPointer set to:  %lu\n", wolfStackPointer);
        wolfFuncOverhead = wolfStackPointer - end;
        if (wolfFuncOverhead > 0) {
            printf("Detected overhead cost associated with simply calling a"
                    "function\n");
        }
    }

    static inline void wc_ResetStackStats() {
        stackBytesUsed = 0;
    }

    static inline void wc_PrintStackStats() {
        printf("%lu bytes\n", stackBytesUsed);
    }
#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* WOLFCRYPT_STACK_PROFILER_H */
