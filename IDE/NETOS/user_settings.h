#ifndef _NETOS_USER_SETTINGS_H_
#define _NETOS_USER_SETTINGS_H_

/* Verify this is NetOS */
/*
#ifndef _NETOS
#error This user_settings.h header is only designed for NetOS
#endif
*/

/* Configurations */
#if defined(HAVE_FIPS)
#if defined(WOLFSSL_LIB)
    /* The FIPS lib */
    #define THREADX
    #define BIG_ENDIAN_ORDER
    #define NO_WRITEV
    #define NO_WOLFSSL_DIR
    #define DEBUG_WOLFSSL
    #define NO_DEV_RANDOM
    #define NETOS
    #define NO_FILESYSTEM
    
    #define TFM_TIMING_RESISTANT 
    #define ECC_TIMING_RESISTANT 
    #define WC_RSA_BLINDING 
    #define HAVE_AESGCM 
    #define WOLFSSL_SHA512 
    #define WOLFSSL_SHA384 
    #define NO_DSA 
    #define HAVE_ECC 
    #define TFM_ECC256 
    #define ECC_SHAMIR 
    #define WOLFSSL_BASE64_ENCODE 
    #define NO_RC4 
    #define NO_HC128 
    #define NO_RABBIT 
    #define HAVE_HASHDRBG 
    #define HAVE_TLS_EXTENSIONS 
    #define HAVE_SUPPORTED_CURVES 
    #define HAVE_EXTENDED_MASTER 
    #define NO_PSK 
    #define NO_MD4 
    #define NO_PWDBASED 
    #define USE_FAST_MATH 
    #define WC_NO_ASYNC_THREADING
    
    #define WC_RSAKEY_TYPE_DEFINED
    #define WC_RNG_TYPE_DEFINED
    
    #define NO_TESTSUITE_MAIN_DRIVER
    #define NO_MAIN_DRIVER

    extern unsigned char get_byte_from_pool(void);
    #define CUSTOM_RAND_GENERATE  get_byte_from_pool
    #define CUSTOM_RAND_TYPE      unsigned char
    
    #define OPENSSL_EXTRA
    #define HAVE_LIGHTY
    #define WOLFSSL_AES_DIRECT
    
    #define WOLFSSL_MYSQL_COMPATIBLE
#else
    /* The FIPS apps */
    #define THREADX
    #define BIG_ENDIAN_ORDER
    #define NO_WRITEV
    #define NO_WOLFSSL_DIR
    #define DEBUG_WOLFSSL
    #define NO_DEV_RANDOM
    #define NETOS
    #define NO_FILESYSTEM
    
    #define TFM_TIMING_RESISTANT 
    #define ECC_TIMING_RESISTANT 
    #define WC_RSA_BLINDING 
    #define HAVE_AESGCM 
    #define WOLFSSL_SHA512 
    #define WOLFSSL_SHA384 
    #define NO_DSA 
    #define HAVE_ECC 
    #define TFM_ECC256 
    #define ECC_SHAMIR 
    #define WOLFSSL_BASE64_ENCODE 
    #define NO_RC4 
    #define NO_HC128 
    #define NO_RABBIT 
    #define HAVE_HASHDRBG 
    #define HAVE_TLS_EXTENSIONS 
    #define HAVE_SUPPORTED_CURVES 
    #define HAVE_EXTENDED_MASTER 
    #define NO_PSK 
    #define NO_MD4 
    #define NO_PWDBASED 
    #define USE_FAST_MATH 
    #define WC_NO_ASYNC_THREADING
    
    #define WC_RSAKEY_TYPE_DEFINED
    #define WC_RNG_TYPE_DEFINED
    
    #define NO_TESTSUITE_MAIN_DRIVER
    #define NO_MAIN_DRIVER
    
    #define OPENSSL_EXTRA
    #define HAVE_LIGHTY
    #define WOLFSSL_AES_DIRECT
    
    #define WOLFSSL_MYSQL_COMPATIBLE
#endif
#else /* HAVE_FIPS */
#if defined(WOLFSSL_LIB)
    /* The NON-FIPS lib */
    #define THREADX
    #define BIG_ENDIAN_ORDER
    //#define OPENSSL_EXTRA
    #define WOLFSSL_RIPEMD
    #define WOLFSSL_SHA512
    #define NO_PSK
    #define HAVE_EXTENDED_MASTER
    #define WOLFSSL_SNIFFER
    #define HAVE_TLS_EXTENSIONS
    #define HAVE_SECURE_RENEGOTIATION
    #define NO_WRITEV
    #define NO_WOLFSSL_DIR
    #define DEBUG_WOLFSSL
    #define NO_DEV_RANDOM
    #define NETOS
    #define NO_FILESYSTEM
#else
    /* The NON-FIPS apps */
    #define THREADX
    #define BIG_ENDIAN_ORDER
    //#define OPENSSL_EXTRA
    #define NO_PSK
    #define HAVE_EXTENDED_MASTER
    #define WOLFSSL_SNIFFER
    #define HAVE_SECURE_RENEGOTIATION
    #define NO_WRITEV
    #define NO_WOLFSSL_DIR
    #define WOLFSSL_NO_CURRDIR
    #define DEBUG_WOLFSSL
    #define NETOS
    #define NO_FILESYSTEM
#endif
#endif /* HAVE_FIPS */

#endif /* _NETOS_USER_SETTINGS_H_ */
