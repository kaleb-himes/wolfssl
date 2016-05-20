/* wc_stack_profiler.c
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

/* Macro to enable stack profiling */
#ifdef WOLFCRYPT_PROFILE_STACK

#include <string.h>

#ifdef FREESCALE_MQX
    #include <mqx.h>
    #if MQX_USE_IO_OLD
        #include <fio.h>
    #else
        #include <nio.h>
    #endif
#else
    #include <stdio.h>
#endif

#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/des3.h>
#include <wolfssl/wolfcrypt/arc4.h>
#include <wolfssl/wolfcrypt/hc128.h>
#include <wolfssl/wolfcrypt/rabbit.h>
#include <wolfssl/wolfcrypt/chacha.h>
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/poly1305.h>
#include <wolfssl/wolfcrypt/camellia.h>
#include <wolfssl/wolfcrypt/md5.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/ripemd.h>
#ifdef HAVE_ECC
    #include <wolfssl/wolfcrypt/ecc.h>
#endif
#ifdef HAVE_IDEA
    #include <wolfssl/wolfcrypt/idea.h>
#endif
#ifdef HAVE_CURVE25519
    #include <wolfssl/wolfcrypt/curve25519.h>
#endif
#ifdef HAVE_ED25519
    #include <wolfssl/wolfcrypt/ed25519.h>
#endif

#include <wolfssl/wolfcrypt/dh.h>
#ifdef HAVE_CAVIUM
    #include "cavium_sysdep.h"
    #include "cavium_common.h"
    #include "cavium_ioctl.h"
#endif
#ifdef HAVE_NTRU
    #include "libntruencrypt/ntru_crypto.h"
#endif
#include <wolfssl/wolfcrypt/random.h>

#ifdef HAVE_WNR
    const char* wnrConfigFile = "wnr-example.conf";
#endif

#if defined(WOLFSSL_MDK_ARM)
    extern FILE * wolfSSL_fopen(const char *fname, const char *mode) ;
    #define fopen wolfSSL_fopen
#endif

/* let's use buffers, we have them */
#if !defined(USE_CERT_BUFFERS_1024) && !defined(USE_CERT_BUFFERS_2048)
    #define USE_CERT_BUFFERS_2048
#endif

#if defined(USE_CERT_BUFFERS_1024) || defined(USE_CERT_BUFFERS_2048) \
                                   || !defined(NO_DH)
    /* include test cert and key buffers for use with NO_FILESYSTEM */
        #include <wolfssl/certs_test.h>
#endif


#ifdef HAVE_BLAKE2
    #include <wolfssl/wolfcrypt/blake2.h>
    void profile_blake2(void);
#endif

#ifdef _MSC_VER
    /* 4996 warning to use MS extensions e.g., strcpy_s instead of strncpy */
    #pragma warning(disable: 4996)
#endif

#include "wolfcrypt/benchmark/benchmark.h"

#ifdef USE_WOLFSSL_MEMORY
    #include "wolfssl/wolfcrypt/mem_track.h"
#endif

extern size_t wolfStackPointer;
extern size_t wolfFuncOverhead;

#include "wolfcrypt/benchmark/wc_stack_profiler.h"

void profile_des(void);
void profile_idea(void);
void profile_arc4(void);
void profile_hc128(void);
void profile_rabbit(void);
void profile_chacha(void);
void profile_chacha20_poly1305_aead(void);
void profile_aes(int);
void profile_aesgcm(void);
void profile_aesccm(void);
void profile_aesctr(void);
void profile_poly1305(void);
void profile_camellia(void);

void profile_md5(void);
void profile_sha(void);
void profile_sha256(void);
void profile_sha384(void);
void profile_sha512(void);
void profile_ripemd(void);

void profile_rsa(void);
void profile_rsaKeyGen(void);
void profile_dh(void);
#ifdef HAVE_ECC
void profile_eccKeyGen(void);
void profile_eccKeyAgree(void);
#endif
#ifdef HAVE_CURVE25519
    void profile_curve25519KeyGen(void);
    #ifdef HAVE_CURVE25519_SHARED_SECRET
        void profile_curve25519KeyAgree(void);
    #endif /* HAVE_CURVE25519_SHARED_SECRET */
#endif /* HAVE_CURVE25519 */
#ifdef HAVE_ED25519
void profile_ed25519KeyGen(void);
void profile_ed25519KeySign(void);
#endif
#ifdef HAVE_NTRU
void profile_ntru(void);
void profile_ntruKeyGen(void);
#endif
void profile_rng(void);

#ifdef HAVE_CAVIUM

static int OpenNitroxDevice(int dma_mode,int dev_id)
{
   Csp1CoreAssignment core_assign;
   Uint32             device;

   if (CspInitialize(CAVIUM_DIRECT,CAVIUM_DEV_ID))
      return -1;
   if (Csp1GetDevType(&device))
      return -1;
   if (device != NPX_DEVICE) {
      if (ioctl(gpkpdev_hdlr[CAVIUM_DEV_ID], IOCTL_CSP1_GET_CORE_ASSIGNMENT,
                (Uint32 *)&core_assign)!= 0)
         return -1;
   }
   CspShutdown(CAVIUM_DEV_ID);

   return CspInitialize(dma_mode, dev_id);
}

#endif

#if defined(DEBUG_WOLFSSL) && !defined(HAVE_VALGRIND)
    WOLFSSL_API int wolfSSL_Debugging_ON();
#endif

#if !defined(NO_RSA) || !defined(NO_DH) \
                        || defined(WOLFSSL_KEYGEN) || defined(HAVE_ECC) \
                        || defined(HAVE_CURVE25519) || defined(HAVE_ED25519)
    #define HAVE_LOCAL_RNG
    static WC_RNG rng;
#endif

/* use kB instead of mB for embedded benchmarking */
#ifdef BENCH_EMBEDDED
    static byte plain [1024];
#else
    static byte plain [1024*1024];
#endif


/* use kB instead of mB for embedded benchmarking */
#ifdef BENCH_EMBEDDED
    static byte cipher[1024];
#else
    static byte cipher[1024*1024];
#endif


static const XGEN_ALIGN byte key[] =
{
    0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
    0xfe,0xde,0xba,0x98,0x76,0x54,0x32,0x10,
    0x89,0xab,0xcd,0xef,0x01,0x23,0x45,0x67
};

static const XGEN_ALIGN byte iv[] =
{
    0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef,
    0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
    0x11,0x21,0x31,0x41,0x51,0x61,0x71,0x81
};


/* so embedded projects can pull in tests on their own */
int stack_profile_test(void *args)
{
    (void)args;

    wolfStackPointer = wc_GetStackPosition();
    wc_CalcFuncOverhead(wolfStackPointer);
    if (wolfFuncOverhead > 0) {
        printf("WARNING: In this environ there appears to be an overhead cost\n"
                "for calling a function. That cost is approx: %lu bytes\n\n",
                                                             wolfFuncOverhead);
    }
#if defined(USE_WOLFSSL_MEMORY) && defined(WOLFSSL_TRACK_MEMORY)
    InitMemoryTracker();
#endif

    wolfCrypt_Init();

    #if defined(DEBUG_WOLFSSL) && !defined(HAVE_VALGRIND)
        wolfSSL_Debugging_ON();
    #endif

    (void)plain;
    (void)cipher;
    (void)key;
    (void)iv;

    #ifdef HAVE_CAVIUM
    int ret = OpenNitroxDevice(CAVIUM_DIRECT, CAVIUM_DEV_ID);
    if (ret != 0) {
        printf("Cavium OpenNitroxDevice failed\n");
        exit(-1);
    }
    #endif /* HAVE_CAVIUM */

    #ifdef HAVE_WNR
    if (wc_InitNetRandom(wnrConfigFile, NULL, 5000) != 0) {
        printf("Whitewood netRandom config init failed\n");
        exit(-1);
    }
    #endif /* HAVE_WNR */

#if defined(HAVE_LOCAL_RNG)
    {
        int rngRet = wc_InitRng(&rng);
        if (rngRet < 0) {
            printf("InitRNG failed\n");
            return rngRet;
        }
    }
#endif

    profile_rng();
#ifndef NO_AES
#ifdef HAVE_AES_CBC
    profile_aes(0);
    profile_aes(1);
#endif
#ifdef HAVE_AESGCM
        profile_aesgcm();
#endif
#ifdef WOLFSSL_AES_COUNTER
        profile_aesctr();
#endif
#ifdef HAVE_AESCCM
        profile_aesccm();
#endif
#endif /* !NO_AES */

#ifdef HAVE_CAMELLIA
        profile_camellia();
#endif
#ifndef NO_RC4
        profile_arc4();
#endif
#ifdef HAVE_HC128
    profile_hc128();
#endif
#ifndef NO_RABBIT
    profile_rabbit();
#endif
#ifdef HAVE_CHACHA
        profile_chacha();
#endif
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
        profile_chacha20_poly1305_aead();
#endif
#ifndef NO_DES3
    profile_des();
#endif
#ifdef HAVE_IDEA
    profile_idea();
#endif

    printf("\n");

#ifndef NO_MD5
    profile_md5();
#endif
#ifdef HAVE_POLY1305
    profile_poly1305();
#endif
#ifndef NO_SHA
        profile_sha();
#endif
#ifndef NO_SHA256
        profile_sha256();
#endif
#ifdef WOLFSSL_SHA384
        profile_sha384();
#endif
#ifdef WOLFSSL_SHA512
        profile_sha512();
#endif
#ifdef WOLFSSL_RIPEMD
    profile_ripemd();
#endif
#ifdef HAVE_BLAKE2
    profile_blake2();
#endif

    printf("\n");

#ifndef NO_RSA
    profile_rsa();
#endif

#ifndef NO_DH
    profile_dh();
#endif

#if defined(WOLFSSL_KEY_GEN) && !defined(NO_RSA)
    profile_rsaKeyGen();
#endif

#ifdef HAVE_NTRU
    profile_ntru();
    profile_ntruKeyGen();
#endif

#ifdef HAVE_ECC
    profile_eccKeyGen();
    profile_eccKeyAgree();
    #if defined(FP_ECC)
        wc_ecc_fp_free();
    #endif
#endif

#ifdef HAVE_CURVE25519
    profile_curve25519KeyGen();
    #ifdef HAVE_CURVE25519_SHARED_SECRET
        profile_curve25519KeyAgree();
    #endif
#endif

#ifdef HAVE_ED25519
    profile_ed25519KeyGen();
    profile_ed25519KeySign();
#endif

#if defined(HAVE_LOCAL_RNG)
    wc_FreeRng(&rng);
#endif

#ifdef HAVE_WNR
    if (wc_FreeNetRandom() < 0) {
        printf("Failed to free netRandom context\n");
        exit(-1);
    }
#endif

#if defined(USE_WOLFSSL_MEMORY) && defined(WOLFSSL_TRACK_MEMORY)
    ShowMemoryTracker();
#endif

    return 0;
}


#ifdef BENCH_EMBEDDED
enum BenchmarkBounds {
    numBlocks  = 25, /* how many kB to test (en/de)cryption */
    ntimes     = 1,
    genTimes   = 5,  /* public key iterations */
    agreeTimes = 5
};
static const char blockType[] = "kB";   /* used in printf output */
#else
enum BenchmarkBounds {
    numBlocks  = 50,  /* how many megs to test (en/de)cryption */
    ntimes     = 100,
    genTimes   = 100,
    agreeTimes = 100
};
#endif

void profile_rng(void)
{
    int    ret, i;
    int pos, len, remain;
    size_t end, usage;
#ifndef HAVE_LOCAL_RNG
    WC_RNG rng;
#endif

#ifndef HAVE_LOCAL_RNG
    ret = wc_InitRng(&rng);
    if (ret < 0) {
        printf("InitRNG failed\n");
        return;
    }
#endif

    for(i = 0; i < numBlocks; i++) {
        /* Split request to handle large RNG request */
        pos = 0;
        remain = (int)sizeof(plain);
        while (remain > 0) {
            len = remain;
            if (len > RNG_MAX_BLOCK_LEN)
                len = RNG_MAX_BLOCK_LEN;
            ret = wc_RNG_GenerateBlock(&rng, &plain[pos], len);
            if (ret < 0) {
                printf("wc_RNG_GenerateBlock failed %d\n", ret);
                break;
            }
            remain -= len;
            pos += len;
        }
    }
#ifndef HAVE_LOCAL_RNG
    wc_FreeRng(&rng);
#endif
    end = wc_GetStackPosition();
    usage = wc_CalcStackUsage(wolfStackPointer, end);
    printf("RNG      stack usage:  %lu bytes\n", usage);
}


#ifndef NO_AES

#ifdef HAVE_AES_CBC
void profile_aes(int show)
{
    Aes    enc;
    int    i;
    int    ret;
    (void) show;
    size_t end, usage;

#ifdef HAVE_CAVIUM
    if (wc_AesInitCavium(&enc, CAVIUM_DEV_ID) != 0) {
        printf("aes init cavium failed\n");
        return;
    }
#endif

    ret = wc_AesSetKey(&enc, key, 16, iv, AES_ENCRYPTION);
    if (ret != 0) {
        printf("AesSetKey failed, ret = %d\n", ret);
        return;
    }

    for(i = 0; i < numBlocks; i++)
        wc_AesCbcEncrypt(&enc, plain, cipher, sizeof(plain));

#ifdef HAVE_CAVIUM
    wc_AesFreeCavium(&enc);
    if (wc_AesInitCavium(&enc, CAVIUM_DEV_ID) != 0) {
        printf("aes init cavium failed\n");
        return;
    }
#endif

    ret = wc_AesSetKey(&enc, key, 16, iv, AES_DECRYPTION);
    if (ret != 0) {
        printf("AesSetKey failed, ret = %d\n", ret);
        return;
    }

    for(i = 0; i < numBlocks; i++)
        wc_AesCbcDecrypt(&enc, plain, cipher, sizeof(plain));

#ifdef HAVE_CAVIUM
    wc_AesFreeCavium(&enc);
#endif
    end = wc_GetStackPosition();
    usage = wc_CalcStackUsage(wolfStackPointer, end);
    printf("AES      stack usage:  %lu bytes\n", usage);
}
#endif /* HAVE_AES_CBC */

#if defined(HAVE_AESGCM) || defined(HAVE_AESCCM)
    static byte additional[13];
    static byte tag[16];
#endif


#ifdef HAVE_AESGCM
void profile_aesgcm(void)
{
    Aes    enc;
    int    i;
    size_t end, usage;

    wc_AesGcmSetKey(&enc, key, 16);

    for(i = 0; i < numBlocks; i++)
        wc_AesGcmEncrypt(&enc, cipher, plain, sizeof(plain), iv, 12,
                        tag, 16, additional, 13);
    end = wc_GetStackPosition();
    usage = wc_CalcStackUsage(wolfStackPointer, end);
    printf("AES-GCM  stack usage:  %lu bytes\n", usage);
}
#endif /* HAVE_AESGCM */


#ifdef WOLFSSL_AES_COUNTER
void profile_aesctr(void)
{
    Aes    enc;
    int    i;
    size_t end, usage;

    wc_AesSetKeyDirect(&enc, key, AES_BLOCK_SIZE, iv, AES_ENCRYPTION);

    for(i = 0; i < numBlocks; i++)
        wc_AesCtrEncrypt(&enc, plain, cipher, sizeof(plain));

    end = wc_GetStackPosition();
    usage = wc_CalcStackUsage(wolfStackPointer, end);
    printf("AES-CTR  stack usage:  %lu bytes\n", usage);
}
#endif /* WOLFSSL_AES_COUNTER */


#ifdef HAVE_AESCCM
void profile_aesccm(void)
{
    Aes    enc;
    int    i;
    size_t end, usage;

    wc_AesCcmSetKey(&enc, key, 16);

    for(i = 0; i < numBlocks; i++)
        wc_AesCcmEncrypt(&enc, cipher, plain, sizeof(plain), iv, 12,
                        tag, 16, additional, 13);
    end = wc_GetStackPosition();
    usage = wc_CalcStackUsage(wolfStackPointer, end);
    printf("AES-CCM  stack usage:  %lu bytes\n", usage);
}
#endif /* HAVE_AESCCM */
#endif /* !NO_AES */


#ifdef HAVE_POLY1305
void profile_poly1305()
{
    Poly1305    enc;
    byte   mac[16];
    int    i;
    int    ret;
    size_t end, usage;

    ret = wc_Poly1305SetKey(&enc, key, 32);
    if (ret != 0) {
        printf("Poly1305SetKey failed, ret = %d\n", ret);
        return;
    }

    for(i = 0; i < numBlocks; i++)
        wc_Poly1305Update(&enc, plain, sizeof(plain));

    wc_Poly1305Final(&enc, mac);
    end = wc_GetStackPosition();
    usage = wc_CalcStackUsage(wolfStackPointer, end);
    printf("POLY1305 stack usage:  %lu bytes\n", usage);
}
#endif /* HAVE_POLY1305 */


#ifdef HAVE_CAMELLIA
void profile_camellia(void)
{
    Camellia cam;
    int    i, ret;
    size_t end, usage;

    ret = wc_CamelliaSetKey(&cam, key, 16, iv);
    if (ret != 0) {
        printf("CamelliaSetKey failed, ret = %d\n", ret);
        return;
    }

    for(i = 0; i < numBlocks; i++)
        wc_CamelliaCbcEncrypt(&cam, plain, cipher, sizeof(plain));
    end = wc_GetStackPosition();
    usage = wc_CalcStackUsage(wolfStackPointer, end);
    printf("CAMELLIA stack usage:  %lu bytes\n", usage);
}
#endif


#ifndef NO_DES3
void profile_des(void)
{
    Des3   enc;
    int    i, ret;
    size_t end, usage;

#ifdef HAVE_CAVIUM
    if (wc_Des3_InitCavium(&enc, CAVIUM_DEV_ID) != 0)
        printf("des3 init cavium failed\n");
#endif
    ret = wc_Des3_SetKey(&enc, key, iv, DES_ENCRYPTION);
    if (ret != 0) {
        printf("Des3_SetKey failed, ret = %d\n", ret);
        return;
    }

    for(i = 0; i < numBlocks; i++)
        wc_Des3_CbcEncrypt(&enc, plain, cipher, sizeof(plain));
#ifdef HAVE_CAVIUM
    wc_Des3_FreeCavium(&enc);
#endif
    end = wc_GetStackPosition();
    usage = wc_CalcStackUsage(wolfStackPointer, end);
    printf("DES      stack usage:  %lu bytes\n", usage);
}
#endif


#ifdef HAVE_IDEA
void profile_idea(void)
{
    Idea   enc;
    int    i, ret;
    size_t end, usage;

    ret = wc_IdeaSetKey(&enc, key, IDEA_KEY_SIZE, iv, IDEA_ENCRYPTION);
    if (ret != 0) {
        printf("Des3_SetKey failed, ret = %d\n", ret);
        return;
    }

    for(i = 0; i < numBlocks; i++)
        wc_IdeaCbcEncrypt(&enc, plain, cipher, sizeof(plain));
    end = wc_GetStackPosition();
    usage = wc_CalcStackUsage(wolfStackPointer, end);
    printf("IDEA     stack usage:  %lu bytes\n", usage);
}
#endif /* HAVE_IDEA */


#ifndef NO_RC4
void profile_arc4(void)
{
    Arc4   enc;
    int    i;
    size_t end, usage;

#ifdef HAVE_CAVIUM
    if (wc_Arc4InitCavium(&enc, CAVIUM_DEV_ID) != 0)
        printf("arc4 init cavium failed\n");
#endif

    wc_Arc4SetKey(&enc, key, 16);

    for(i = 0; i < numBlocks; i++)
        wc_Arc4Process(&enc, cipher, plain, sizeof(plain));

#ifdef HAVE_CAVIUM
    wc_Arc4FreeCavium(&enc);
#endif
    end = wc_GetStackPosition();
    usage = wc_CalcStackUsage(wolfStackPointer, end);
    printf("ARC4     stack usage:  %lu bytes\n", usage);
}
#endif


#ifdef HAVE_HC128
void profile_hc128(void)
{
    HC128  enc;
    int    i;
    size_t end, usage;

    wc_Hc128_SetKey(&enc, key, iv);

    for(i = 0; i < numBlocks; i++)
        wc_Hc128_Process(&enc, cipher, plain, sizeof(plain));
    end = wc_GetStackPosition();
    usage = wc_CalcStackUsage(wolfStackPointer, end);
    printf("HC128    stack usage:  %lu bytes\n", usage);
}
#endif /* HAVE_HC128 */


#ifndef NO_RABBIT
void profile_rabbit(void)
{
    Rabbit  enc;
    int    i;
    size_t end, usage;

    wc_RabbitSetKey(&enc, key, iv);

    for(i = 0; i < numBlocks; i++)
        wc_RabbitProcess(&enc, cipher, plain, sizeof(plain));
    end = wc_GetStackPosition();
    usage = wc_CalcStackUsage(wolfStackPointer, end);
    printf("RABBIT   stack usage:  %lu bytes\n", usage);
}
#endif /* NO_RABBIT */


#ifdef HAVE_CHACHA
void profile_chacha(void)
{
    ChaCha enc;
    int    i;
    size_t end, usage;

    wc_Chacha_SetKey(&enc, key, 16);

    for (i = 0; i < numBlocks; i++) {
        wc_Chacha_SetIV(&enc, iv, 0);
        wc_Chacha_Process(&enc, cipher, plain, sizeof(plain));
    }
    end = wc_GetStackPosition();
    usage = wc_CalcStackUsage(wolfStackPointer, end);
    printf("CHACHA   stack usage:  %lu bytes\n", usage);
}
#endif /* HAVE_CHACHA*/

#if( defined( HAVE_CHACHA ) && defined( HAVE_POLY1305 ) )
void profile_chacha20_poly1305_aead(void)
{
    int    i;
    size_t end, usage;

    byte authTag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];
    XMEMSET( authTag, 0, sizeof( authTag ) );

    for (i = 0; i < numBlocks; i++)
    {
        wc_ChaCha20Poly1305_Encrypt(key, iv, NULL, 0, plain, sizeof(plain),
                                    cipher, authTag );
    }
    end = wc_GetStackPosition();
    usage = wc_CalcStackUsage(wolfStackPointer, end);
    printf("CHACHA-POLY-AEAD   stack usage:  %lu bytes\n", usage);
}
#endif /* HAVE_CHACHA && HAVE_POLY1305 */


#ifndef NO_MD5
void profile_md5(void)
{
    Md5    hash;
    byte   digest[MD5_DIGEST_SIZE];
    int    i;
    size_t end, usage;

    wc_InitMd5(&hash);

    for(i = 0; i < numBlocks; i++)
        wc_Md5Update(&hash, plain, sizeof(plain));

    wc_Md5Final(&hash, digest);
    end = wc_GetStackPosition();
    usage = wc_CalcStackUsage(wolfStackPointer, end);
    printf("MD5      stack usage:  %lu bytes\n", usage);
}
#endif /* NO_MD5 */


#ifndef NO_SHA
void profile_sha(void)
{
    Sha    hash;
    byte   digest[SHA_DIGEST_SIZE];
    int    i, ret;
    size_t end, usage;

    ret = wc_InitSha(&hash);
    if (ret != 0) {
        printf("InitSha failed, ret = %d\n", ret);
        return;
    }

    for(i = 0; i < numBlocks; i++)
        wc_ShaUpdate(&hash, plain, sizeof(plain));

    wc_ShaFinal(&hash, digest);

    end = wc_GetStackPosition();
    usage = wc_CalcStackUsage(wolfStackPointer, end);
    printf("SHA      stack usage:  %lu bytes\n", usage);
}
#endif /* NO_SHA */


#ifndef NO_SHA256
void profile_sha256(void)
{
    Sha256 hash;
    byte   digest[SHA256_DIGEST_SIZE];
    int    i, ret;
    size_t end, usage;

    ret = wc_InitSha256(&hash);
    if (ret != 0) {
        printf("InitSha256 failed, ret = %d\n", ret);
        return;
    }

    for(i = 0; i < numBlocks; i++) {
        ret = wc_Sha256Update(&hash, plain, sizeof(plain));
        if (ret != 0) {
            printf("Sha256Update failed, ret = %d\n", ret);
            return;
        }
    }

    ret = wc_Sha256Final(&hash, digest);
    if (ret != 0) {
        printf("Sha256Final failed, ret = %d\n", ret);
        return;
    }

    end = wc_GetStackPosition();
    usage = wc_CalcStackUsage(wolfStackPointer, end);
    printf("SHA-256  stack usage:  %lu bytes\n", usage);
}
#endif

#ifdef WOLFSSL_SHA384
void profile_sha384(void)
{
    Sha384 hash;
    byte   digest[SHA384_DIGEST_SIZE];
    int    i, ret;
    size_t end, usage;

    ret = wc_InitSha384(&hash);
    if (ret != 0) {
        printf("InitSha384 failed, ret = %d\n", ret);
        return;
    }

    for(i = 0; i < numBlocks; i++) {
        ret = wc_Sha384Update(&hash, plain, sizeof(plain));
        if (ret != 0) {
            printf("Sha384Update failed, ret = %d\n", ret);
            return;
        }
    }

    ret = wc_Sha384Final(&hash, digest);
    if (ret != 0) {
        printf("Sha384Final failed, ret = %d\n", ret);
        return;
    }
    end = wc_GetStackPosition();
    usage = wc_CalcStackUsage(wolfStackPointer, end);
    printf("SHA-384  stack usage:  %lu bytes\n", usage);
}
#endif

#ifdef WOLFSSL_SHA512
void profile_sha512(void)
{
    Sha512 hash;
    byte   digest[SHA512_DIGEST_SIZE];
    int    i, ret;
    size_t end, usage;

    ret = wc_InitSha512(&hash);
    if (ret != 0) {
        printf("InitSha512 failed, ret = %d\n", ret);
        return;
    }

    for(i = 0; i < numBlocks; i++) {
        ret = wc_Sha512Update(&hash, plain, sizeof(plain));
        if (ret != 0) {
            printf("Sha512Update failed, ret = %d\n", ret);
            return;
        }
    }

    ret = wc_Sha512Final(&hash, digest);
    if (ret != 0) {
        printf("Sha512Final failed, ret = %d\n", ret);
        return;
    }
    end = wc_GetStackPosition();
    usage = wc_CalcStackUsage(wolfStackPointer, end);
    printf("SHA-512  stack usage:  %lu bytes\n", usage);
}
#endif

#ifdef WOLFSSL_RIPEMD
void profile_ripemd(void)
{
    RipeMd hash;
    byte   digest[RIPEMD_DIGEST_SIZE];
    int    i;
    size_t end, usage;

    wc_InitRipeMd(&hash);

    for(i = 0; i < numBlocks; i++)
        wc_RipeMdUpdate(&hash, plain, sizeof(plain));

    wc_RipeMdFinal(&hash, digest);
    end = wc_GetStackPosition();
    usage = wc_CalcStackUsage(wolfStackPointer, end);
    printf("RIPEMD   stack usage:  %lu bytes\n", usage);
}
#endif


#ifdef HAVE_BLAKE2
void profile_blake2(void)
{
    Blake2b b2b;
    byte    digest[64];
    int     i, ret;
    size_t end, usage;

    ret = wc_InitBlake2b(&b2b, 64);
    if (ret != 0) {
        printf("InitBlake2b failed, ret = %d\n", ret);
        return;
    }

    for(i = 0; i < numBlocks; i++) {
        ret = wc_Blake2bUpdate(&b2b, plain, sizeof(plain));
        if (ret != 0) {
            printf("Blake2bUpdate failed, ret = %d\n", ret);
            return;
        }
    }

    ret = wc_Blake2bFinal(&b2b, digest, 64);
    if (ret != 0) {
        printf("Blake2bFinal failed, ret = %d\n", ret);
        return;
    }
    end = wc_GetStackPosition();
    usage = wc_CalcStackUsage(wolfStackPointer, end);
    printf("BLAKE2   stack usage:  %lu bytes\n", usage);
}
#endif


#ifndef NO_RSA


#if !defined(USE_CERT_BUFFERS_1024) && !defined(USE_CERT_BUFFERS_2048)
    #if defined(WOLFSSL_MDK_SHELL)
        static char *certRSAname = "certs/rsa2048.der";
        /* set by shell command */
        static void set_Bench_RSA_File(char * cert) { certRSAname = cert ; }
    #elif defined(FREESCALE_MQX)
        static char *certRSAname = "a:\\certs\\rsa2048.der";
    #else
        static const char *certRSAname = "certs/rsa2048.der";
    #endif
#endif

void profile_rsa(void)
{
    int    i;
    int    ret;
    size_t bytes;
    word32 idx = 0;
    const byte* tmp;
    size_t end, usage;

    byte      message[] = "Everyone gets Friday off.";
    byte      enc[256];  /* for up to 2048 bit */
    const int len = (int)strlen((char*)message);

    RsaKey rsaKey;

#ifdef USE_CERT_BUFFERS_1024
    tmp = rsa_key_der_1024;
    bytes = sizeof_rsa_key_der_1024;
#elif defined(USE_CERT_BUFFERS_2048)
    tmp = rsa_key_der_2048;
    bytes = sizeof_rsa_key_der_2048;
#else
    #error "need a cert buffer size"
#endif /* USE_CERT_BUFFERS */


#ifdef HAVE_CAVIUM
    if (wc_RsaInitCavium(&rsaKey, CAVIUM_DEV_ID) != 0)
        printf("RSA init cavium failed\n");
#endif
    ret = wc_InitRsaKey(&rsaKey, 0);
    if (ret < 0) {
        printf("InitRsaKey failed\n");
        return;
    }
    ret = wc_RsaPrivateKeyDecode(tmp, &idx, &rsaKey, (word32)bytes);

    for (i = 0; i < ntimes; i++)
        ret = wc_RsaPublicEncrypt(message,len,enc,sizeof(enc), &rsaKey, &rng);

    if (ret < 0) {
        printf("Rsa Public Encrypt failed\n");
        return;
    }

    for (i = 0; i < ntimes; i++) {
         byte  out[256];  /* for up to 2048 bit */
         wc_RsaPrivateDecrypt(enc, (word32)ret, out, sizeof(out), &rsaKey);
    }

    wc_FreeRsaKey(&rsaKey);
#ifdef HAVE_CAVIUM
    wc_RsaFreeCavium(&rsaKey);
#endif
    end = wc_GetStackPosition();
    usage = wc_CalcStackUsage(wolfStackPointer, end);
    printf("RSA      stack usage:  %lu bytes\n", usage);
}
#endif


#ifndef NO_DH


#if !defined(USE_CERT_BUFFERS_1024) && !defined(USE_CERT_BUFFERS_2048)
    #if defined(WOLFSSL_MDK_SHELL)
        static char *certDHname = "certs/dh2048.der";
        /* set by shell command */
        void set_Bench_DH_File(char * cert) { certDHname = cert ; }
    #elif defined(FREESCALE_MQX)
        static char *certDHname = "a:\\certs\\dh2048.der";
    #elif defined(NO_ASN)
        /* do nothing, but don't need a file */
    #else
        static const char *certDHname = "certs/dh2048.der";
    #endif
#endif

void profile_dh(void)
{
    int    i ;
    size_t bytes;
    word32 idx = 0, pubSz, privSz = 0, pubSz2, privSz2, agreeSz;
    const byte* tmp = NULL;
    size_t end, usage;

    byte   pub[256];    /* for 2048 bit */
    byte   pub2[256];   /* for 2048 bit */
    byte   agree[256];  /* for 2048 bit */
    byte   priv[32];    /* for 2048 bit */
    byte   priv2[32];   /* for 2048 bit */

    DhKey  dhKey;

    (void)idx;
    (void)tmp;


#if defined(NO_ASN)
    /* do nothing, but don't use default FILE */
#elif defined(USE_CERT_BUFFERS_1024)
    tmp = dh_key_der_1024;
    bytes = sizeof_dh_key_der_1024;
#elif defined(USE_CERT_BUFFERS_2048)
    tmp = dh_key_der_2048;
    bytes = sizeof_dh_key_der_2048;
#else
    #error "need to define a cert buffer size"
#endif /* USE_CERT_BUFFERS */


    wc_InitDhKey(&dhKey);
#ifdef NO_ASN
    bytes = wc_DhSetKey(&dhKey, dh_p, sizeof(dh_p), dh_g, sizeof(dh_g));
#else
    bytes = wc_DhKeyDecode(tmp, &idx, &dhKey, (word32)bytes);
#endif
    if (bytes != 0) {
        printf("dhekydecode failed, can't benchmark\n");
        return;
    }

    for (i = 0; i < ntimes; i++)
        wc_DhGenerateKeyPair(&dhKey, &rng, priv, &privSz, pub, &pubSz);

    wc_DhGenerateKeyPair(&dhKey, &rng, priv2, &privSz2, pub2, &pubSz2);

    for (i = 0; i < ntimes; i++)
        wc_DhAgree(&dhKey, agree, &agreeSz, priv, privSz, pub2, pubSz2);

    wc_FreeDhKey(&dhKey);
    end = wc_GetStackPosition();
    usage = wc_CalcStackUsage(wolfStackPointer, end);
    printf("DH       stack usage:  %lu bytes\n", usage);
}
#endif

#if defined(WOLFSSL_KEY_GEN) && !defined(NO_RSA)
void profile_rsaKeyGen(void)
{
    RsaKey genKey;
    int    i;
    size_t end, usage;

    /* 1024 bit */

    for(i = 0; i < genTimes; i++) {
        wc_InitRsaKey(&genKey, 0);
        wc_MakeRsaKey(&genKey, 1024, 65537, &rng);
        wc_FreeRsaKey(&genKey);
    }

    /* 2048 bit */

    for(i = 0; i < genTimes; i++) {
        wc_InitRsaKey(&genKey, 0);
        wc_MakeRsaKey(&genKey, 2048, 65537, &rng);
        wc_FreeRsaKey(&genKey);
    }

    end = wc_GetStackPosition();
    usage = wc_CalcStackUsage(wolfStackPointer, end);
    printf("RSA key generation stack usage:  %lu bytes\n", usage);
}
#endif /* WOLFSSL_KEY_GEN */
#ifdef HAVE_NTRU
byte GetEntropy(ENTROPY_CMD cmd, byte* out);

byte GetEntropy(ENTROPY_CMD cmd, byte* out)
{
    if (cmd == INIT)
        return 1; /* using local rng */

    if (out == NULL)
        return 0;

    if (cmd == GET_BYTE_OF_ENTROPY)
        return (wc_RNG_GenerateBlock(&rng, out, 1) == 0) ? 1 : 0;

    if (cmd == GET_NUM_BYTES_PER_BYTE_OF_ENTROPY) {
        *out = 1;
        return 1;
    }

    return 0;
}

void profile_ntru(void)
{
    int    i;
    size_t end, usage;

    byte   public_key[1027];
    word16 public_key_len = sizeof(public_key);
    byte   private_key[1120];
    word16 private_key_len = sizeof(private_key);
    word16 ntruBits = 128;
    word16 type     = 0;
    word32 ret;

    byte ciphertext[1022];
    word16 ciphertext_len;
    byte plaintext[16];
    word16 plaintext_len;

    DRBG_HANDLE drbg;
    static byte const aes_key[] = {
        0xf3, 0xe9, 0x87, 0xbb, 0x18, 0x08, 0x3c, 0xaa,
        0x7b, 0x12, 0x49, 0x88, 0xaf, 0xb3, 0x22, 0xd8
    };

    static byte const wolfsslStr[] = {
        'w', 'o', 'l', 'f', 'S', 'S', 'L', ' ', 'N', 'T', 'R', 'U'
    };

    printf("\n");
    for (ntruBits = 128; ntruBits < 257; ntruBits += 64) {
        switch (ntruBits) {
            case 128:
                type = NTRU_EES439EP1;
                break;
            case 192:
                type = NTRU_EES593EP1;
                break;
            case 256:
                type = NTRU_EES743EP1;
                break;
        }

        ret = ntru_crypto_drbg_instantiate(ntruBits, wolfsslStr,
                sizeof(wolfsslStr), (ENTROPY_FN) GetEntropy, &drbg);
        if(ret != DRBG_OK) {
            printf("NTRU drbg instantiate failed\n");
            return;
        }

        /* set key sizes */
        ret = ntru_crypto_ntru_encrypt_keygen(drbg, type, &public_key_len,
                                                  NULL, &private_key_len, NULL);
        if (ret != NTRU_OK) {
            ntru_crypto_drbg_uninstantiate(drbg);
            printf("NTRU failed to get key lengths\n");
            return;
        }

        ret = ntru_crypto_ntru_encrypt_keygen(drbg, type, &public_key_len,
                                     public_key, &private_key_len,
                                     private_key);

        ntru_crypto_drbg_uninstantiate(drbg);

        if (ret != NTRU_OK) {
            printf("NTRU keygen failed\n");
            return;
        }

        ret = ntru_crypto_drbg_instantiate(ntruBits, NULL, 0,
                (ENTROPY_FN)GetEntropy, &drbg);
        if (ret != DRBG_OK) {
            printf("NTRU error occurred during DRBG instantiation\n");
            return;
        }

        ret = ntru_crypto_ntru_encrypt(drbg, public_key_len, public_key,
                sizeof(aes_key), aes_key, &ciphertext_len, NULL);

        if (ret != NTRU_OK) {
            printf("NTRU error occurred requesting the buffer size needed\n");
            return;
        }
        for (i = 0; i < ntimes; i++) {
            ret = ntru_crypto_ntru_encrypt(drbg, public_key_len, public_key,
                    sizeof(aes_key), aes_key, &ciphertext_len, ciphertext);
            if (ret != NTRU_OK) {
                printf("NTRU encrypt error\n");
                return;
            }
        }
        ret = ntru_crypto_drbg_uninstantiate(drbg);

        if (ret != DRBG_OK) {
            printf("NTRU error occurred uninstantiating the DRBG\n");
            return;
        }

        ret = ntru_crypto_ntru_decrypt(private_key_len, private_key,
                ciphertext_len, ciphertext, &plaintext_len, NULL);

        if (ret != NTRU_OK) {
            printf("NTRU decrypt error occurred getting the buffer size needed\n");
            return;
        }

        plaintext_len = sizeof(plaintext);

        for (i = 0; i < ntimes; i++) {
            ret = ntru_crypto_ntru_decrypt(private_key_len, private_key,
                                      ciphertext_len, ciphertext,
                                      &plaintext_len, plaintext);

            if (ret != NTRU_OK) {
                printf("NTRU error occurred decrypting the key\n");
                return;
            }
        }

    }

    end = wc_GetStackPosition();
    usage = wc_CalcStackUsage(wolfStackPointer, end);
    printf("NTRU     stack usage:  %lu bytes\n", usage);
}

void profile_ntruKeyGen(void)
{
    int    i;
    size_t end, usage;

    byte   public_key[1027];
    word16 public_key_len = sizeof(public_key);
    byte   private_key[1120];
    word16 private_key_len = sizeof(private_key);
    word16 ntruBits = 128;
    word16 type     = 0;
    word32 ret;

    DRBG_HANDLE drbg;
    static uint8_t const pers_str[] = {
                'w', 'o', 'l', 'f',  'S', 'S', 'L', ' ', 't', 'e', 's', 't'
    };

    for (ntruBits = 128; ntruBits < 257; ntruBits += 64) {
        ret = ntru_crypto_drbg_instantiate(ntruBits, pers_str,
                sizeof(pers_str), GetEntropy, &drbg);
        if (ret != DRBG_OK) {
            printf("NTRU drbg instantiate failed\n");
            return;
        }

        switch (ntruBits) {
            case 128:
                type = NTRU_EES439EP1;
                break;
            case 192:
                type = NTRU_EES593EP1;
                break;
            case 256:
                type = NTRU_EES743EP1;
                break;
        }

        /* set key sizes */
        ret = ntru_crypto_ntru_encrypt_keygen(drbg, type, &public_key_len,
                                                  NULL, &private_key_len, NULL);
        for(i = 0; i < genTimes; i++) {
            ret = ntru_crypto_ntru_encrypt_keygen(drbg, type, &public_key_len,
                                         public_key, &private_key_len,
                                         private_key);
        }

        if (ret != NTRU_OK) {
            printf("keygen failed\n");
            return;
        }

        ret = ntru_crypto_drbg_uninstantiate(drbg);

        if (ret != NTRU_OK) {
            printf("NTRU drbg uninstantiate failed\n");
            return;
        }

        each = total / genTimes;
        milliEach = each * 1000;

        printf("NTRU %d key generation  %6.3f milliseconds, avg over %d"
            " iterations\n", ntruBits, milliEach, genTimes);
    }
    end = wc_GetStackPosition();
    usage = wc_CalcStackUsage(wolfStackPointer, end);
    printf("NTRU key generation stack usage:  %lu bytes\n", usage);
}
#endif

#ifdef HAVE_ECC
void profile_eccKeyGen(void)
{
    ecc_key genKey;
    int    i;
    size_t end, usage;

    /* 256 bit */

    for(i = 0; i < genTimes; i++) {
        wc_ecc_init(&genKey);
        wc_ecc_make_key(&rng, 32, &genKey);
        wc_ecc_free(&genKey);
    }
    end = wc_GetStackPosition();
    usage = wc_CalcStackUsage(wolfStackPointer, end);
    printf("ECC key generation stack usage:  %lu bytes\n", usage);
}


void profile_eccKeyAgree(void)
{
    ecc_key genKey, genKey2;
    int    i, ret;
    size_t end, usage;
    byte   shared[32];
#if !defined(NO_ASN) && !defined(NO_ECC_SIGN)
    byte   sig[64+16];  /* der encoding too */
#endif
    byte   digest[32];
    word32 x = 0;

    wc_ecc_init(&genKey);
    wc_ecc_init(&genKey2);

    ret = wc_ecc_make_key(&rng, 32, &genKey);
    if (ret != 0) {
        printf("ecc_make_key failed\n");
        return;
    }
    ret = wc_ecc_make_key(&rng, 32, &genKey2);
    if (ret != 0) {
        printf("ecc_make_key failed\n");
        return;
    }

    /* 256 bit */
    for(i = 0; i < agreeTimes; i++) {
        x = sizeof(shared);
        ret = wc_ecc_shared_secret(&genKey, &genKey2, shared, &x);
        if (ret != 0) {
            printf("ecc_shared_secret failed\n");
            return;
        }
    }


    /* make dummy digest */
    for (i = 0; i < (int)sizeof(digest); i++)
        digest[i] = (byte)i;


#if !defined(NO_ASN) && !defined(NO_ECC_SIGN)

    for(i = 0; i < agreeTimes; i++) {
        x = sizeof(sig);
        ret = wc_ecc_sign_hash(digest, sizeof(digest), sig, &x, &rng, &genKey);
        if (ret != 0) {
            printf("ecc_sign_hash failed\n");
            return;
        }
    }



    for(i = 0; i < agreeTimes; i++) {
        int verify = 0;
        ret = wc_ecc_verify_hash(sig, x, digest, sizeof(digest), &verify, &genKey);
        if (ret != 0) {
            printf("ecc_verify_hash failed\n");
            return;
        }
    }
#endif

    wc_ecc_free(&genKey2);
    wc_ecc_free(&genKey);
    end = wc_GetStackPosition();
    usage = wc_CalcStackUsage(wolfStackPointer, end);
    printf("ECC key agreement stack usage:  %lu bytes\n", usage);
}
#endif /* HAVE_ECC */

#ifdef HAVE_CURVE25519
void profile_curve25519KeyGen(void)
{
    curve25519_key genKey;
    int    i;
    size_t end, usage;

    /* 256 bit */
    for(i = 0; i < genTimes; i++) {
        wc_curve25519_make_key(&rng, 32, &genKey);
        wc_curve25519_free(&genKey);
    }
    end = wc_GetStackPosition();
    usage = wc_CalcStackUsage(wolfStackPointer, end);
    printf("CURVE25519 key generation stack usage:  %lu bytes\n", usage);
}

#ifdef HAVE_CURVE25519_SHARED_SECRET
void profile_curve25519KeyAgree(void)
{
    curve25519_key genKey, genKey2;
    int    i, ret;
    size_t end, usage;
    byte   shared[32];
    word32 x = 0;

    wc_curve25519_init(&genKey);
    wc_curve25519_init(&genKey2);

    ret = wc_curve25519_make_key(&rng, 32, &genKey);
    if (ret != 0) {
        printf("curve25519_make_key failed\n");
        return;
    }
    ret = wc_curve25519_make_key(&rng, 32, &genKey2);
    if (ret != 0) {
        printf("curve25519_make_key failed\n");
        return;
    }

    /* 256 bit */
    for(i = 0; i < agreeTimes; i++) {
        x = sizeof(shared);
        ret = wc_curve25519_shared_secret(&genKey, &genKey2, shared, &x);
        if (ret != 0) {
            printf("curve25519_shared_secret failed\n");
            return;
        }
    }
    wc_curve25519_free(&genKey2);
    wc_curve25519_free(&genKey);
    end = wc_GetStackPosition();
    usage = wc_CalcStackUsage(wolfStackPointer, end);
    printf("CURVE25519 key agreement stack usage:  %lu bytes\n", usage);
}
#endif /* HAVE_CURVE25519_SHARED_SECRET */
#endif /* HAVE_CURVE25519 */

#ifdef HAVE_ED25519
void profile_ed25519KeyGen(void)
{
    ed25519_key genKey;
    int    i;
    size_t end, usage;

    /* 256 bit */
    for(i = 0; i < genTimes; i++) {
        wc_ed25519_init(&genKey);
        wc_ed25519_make_key(&rng, 32, &genKey);
        wc_ed25519_free(&genKey);
    }
    end = wc_GetStackPosition();
    usage = wc_CalcStackUsage(wolfStackPointer, end);
    printf("ED25519 key generation stack usage:  %lu bytes\n", usage);
}


void profile_ed25519KeySign(void)
{
    int    ret;
    size_t end, usage;
    ed25519_key genKey;
#ifdef HAVE_ED25519_SIGN
    int    i;
    byte   sig[ED25519_SIG_SIZE];
    byte   msg[512];
    word32 x = 0;
#endif

    wc_ed25519_init(&genKey);

    ret = wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &genKey);
    if (ret != 0) {
        printf("ed25519_make_key failed\n");
        return;
    }

#ifdef HAVE_ED25519_SIGN
    /* make dummy msg */
    for (i = 0; i < (int)sizeof(msg); i++)
        msg[i] = (byte)i;

    for(i = 0; i < agreeTimes; i++) {
        x = sizeof(sig);
        ret = wc_ed25519_sign_msg(msg, sizeof(msg), sig, &x, &genKey);
        if (ret != 0) {
            printf("ed25519_sign_msg failed\n");
            return;
        }
    }

#ifdef HAVE_ED25519_VERIFY
    for(i = 0; i < agreeTimes; i++) {
        int verify = 0;
        ret = wc_ed25519_verify_msg(sig, x, msg, sizeof(msg), &verify,
                                    &genKey);
        if (ret != 0 || verify != 1) {
            printf("ed25519_verify_msg failed\n");
            return;
        }
    }
#endif /* HAVE_ED25519_VERIFY */
#endif /* HAVE_ED25519_SIGN */

    wc_ed25519_free(&genKey);
    end = wc_GetStackPosition();
    usage = wc_CalcStackUsage(wolfStackPointer, end);
    printf("ED25519 key sign stack usage:  %lu bytes\n", usage);
}
#endif /* HAVE_ED25519 */

size_t wc_CalcStackUsage(size_t startP, size_t endP) {
    size_t ret;
    /* If stack fill direction is top to bottom (back to front) value will be
     * a large negative with start - end as size_t is unsigned
     * if this happens use end - start instead. */
    ret = startP - endP;
    if (ret > WOLFSSL_STACK_SIZE)
        ret = endP - startP;
    if (ret > WOLFSSL_STACK_SIZE)
        printf("ERROR determining stack size for this algorithm\n");
    /* Try to account for overhead on systems where simply creating a function
     * has an overhead cost assosciated with it.
     */
    ret = ret - wolfFuncOverhead;

    /* Deciding if there is a need to detect "Alignment" IE
     * Problem: If there is stack consumption because of "Alignment" should that
     *            be accounted for or included in the calculation as it is
                  associated with the cost of the algorithm.
     */

    return ret;
}
size_t wc_GetStackPosition() {
    size_t* currStackPointer = NULL;
    size_t ret;
    ret = (size_t) &currStackPointer;
    return ret;
}

void wc_CalcFuncOverhead() {
    size_t end = wc_GetStackPosition();
    printf("wolfStackPointer:  %lu\n"
            "end:               %lu\n", wolfStackPointer, end);
    wolfFuncOverhead = wolfStackPointer - end;
}
#endif /* WOLFCRYPT_PROFILE_STACK */

