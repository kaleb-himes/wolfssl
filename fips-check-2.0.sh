#!/bin/bash

# fips-check.sh
# This script checks the current revision of the code against the
# previous release of the FIPS code. While wolfSSL and wolfCrypt
# may be advancing, they must work correctly with the last tested
# copy of our FIPS approved code.
#
# This should check out all the approved versions. The command line
# option selects the version.
#
#     $ ./fips-check [version] [keep]
#
#     - version: linux (default), ios, android, windows, freertos, linux-ecc, netbsd-selftest, linuxv2, fips-ready, stm32l4-v2
#
#     - keep: (default off) XXX-fips-test temp dir around for inspection
#

# ----------------------------------------------------------------------------#
# Usage
Usage() {
    cat <<usageText
Usage: $0 [platform [keep]]
Platform is one of:
    linux (default)
    ios
    android
    windows
    freertos
    openrtos-3.9.2
    linux-ecc
    netbsd-selftest
    sgx
    netos-7.6
    linuxv2 (FIPSv2, use for Win10)
    fips-ready
    stm32l4-v2 (FIPSv2, OpenRTOS v10.1.1 on STM32L4Rx)
    HPIPL-v2   (FIPSv2, HP Imaging & Printing Linux on ARM Cortex-A72)
    WIN_OE3-v2 (FIPSv2, Windows 10 on Intel® Core™ i5-5300U)
    wolfrand
Keep (default off) retains the XXX-fips-test temp dir for inspection.

Example:
    $0 windows keep
usageText
}
# ----------------------------------------------------------------------------#
# Applies to ALL OE's regardless of cert
FIPS_SRCS=( fips.c fips_test.c )
WC_MODS=( aes des3 sha sha256 sha512 rsa hmac random )
TEST_DIR=XXX-fips-test
CRYPT_INC_PATH=cyassl/ctaocrypt
CRYPT_SRC_PATH=ctaocrypt/src
RNG_VERSION=v3.6.0
FIPS_OPTION=v1
CAVP_SELFTEST_ONLY="no"
GIT="git -c advice.detachedHead=false"

if [ "x$1" == "x" ]; then PLATFORM="linux"; else PLATFORM=$1; fi

if [ "x$2" == "xkeep" ]; then KEEP="yes"; else KEEP="no"; fi
# ----------------------------------------------------------------------------#
# Platform setup
case $PLATFORM in
linuxv2)
  FIPS_VERSION=cert-3389-FIPSv2
  FIPS_REPO=git@github.com:kaleb-himes/fips-src.git
  CRYPT_INC_PATH=wolfssl/wolfcrypt
  CRYPT_SRC_PATH=wolfcrypt/src
  WC_MODS+=( cmac dh ecc sha3 )
  FIPS_SRCS+=( wolfcrypt_first.c wolfcrypt_last.c )
  FIPS_INCS=( fips.h )
  FIPS_OPTION=v2
  # modify per-OE:
  CRYPT_OE=ORIGIN
  OE_SRC_MODS=( NONE )
  OE_HDR_MODS=( NONE )
  ;;
stm32l4-v2)
  FIPS_VERSION=cert-3389-FIPSv2
  FIPS_REPO=git@github.com:kaleb-himes/fips-src.git
  CRYPT_INC_PATH=wolfssl/wolfcrypt
  CRYPT_SRC_PATH=wolfcrypt/src
  WC_MODS+=( cmac dh ecc sha3 )
  FIPS_SRCS+=( wolfcrypt_first.c wolfcrypt_last.c )
  FIPS_INCS=( fips.h )
  FIPS_OPTION=v2
  # modify per-OE:
  CRYPT_OE=OE1
  OE_SRC_MODS=( fips.c random.c )
  OE_HDR_MODS=( NONE )
  ;;
HPIPL-v2)
  FIPS_VERSION=cert-3389-FIPSv2
  FIPS_REPO=git@github.com:kaleb-himes/fips-src.git
  CRYPT_INC_PATH=wolfssl/wolfcrypt
  CRYPT_SRC_PATH=wolfcrypt/src
  WC_MODS+=( cmac dh ecc sha3 )
  FIPS_SRCS+=( wolfcrypt_first.c wolfcrypt_last.c )
  FIPS_INCS=( fips.h )
  FIPS_OPTION=v2
  # modify per-OE:
  CRYPT_OE=OE2
  OE_SRC_MODS=( fips.c aes.c sha256.c sha512.c )
  OE_HDR_MODS=( aes.h )
  ;;
WIN_OE3-v2)
  FIPS_VERSION=cert-3389-FIPSv2
  FIPS_REPO=git@github.com:kaleb-himes/fips-src.git
  CRYPT_INC_PATH=wolfssl/wolfcrypt
  CRYPT_SRC_PATH=wolfcrypt/src
  WC_MODS+=( cmac dh ecc sha3 )
  FIPS_SRCS+=( wolfcrypt_first.c wolfcrypt_last.c )
  FIPS_INCS=( fips.h )
  FIPS_OPTION=v2
  # modify per-OE:
  CRYPT_OE=OE3
  OE_SRC_MODS=( fips.c )
  OE_HDR_MODS=( NONE )
  ;;
*)
  Usage
  exit 1
esac
# ----------------------------------------------------------------------------#
# clone local repo into XXX-fips-test
if ! $GIT clone . $TEST_DIR; then
    echo "fips-check: Couldn't duplicate current working directory."
    exit 1
fi

pushd $TEST_DIR || exit 2
FIPS_ROOT_DIR=$(eval "pwd")
# ----------------------------------------------------------------------------#
# Sparse checkout, only checkout the base cert files and the changes for this
# specific Operational Environment addition
mkdir fips-src
cd fips-src
git init
git config core.sparseCheckout true
git remote add -f origin $FIPS_REPO
echo "$FIPS_VERSION/wolfssl" > .git/info/sparse-checkout
echo "$FIPS_VERSION/wolfcrypt" >> .git/info/sparse-checkout
if [ "x$CRYPT_OE" != "xORIGIN" ]; then
    echo "$FIPS_VERSION/$CRYPT_OE" >> .git/info/sparse-checkout
fi
git checkout master
pushd $FIPS_ROOT_DIR || exit 2
# ----------------------------------------------------------------------------#
# Copy the fips versions of the wolfCrypt src and header files from the repo.
for MOD in "${WC_MODS[@]}"
do
    # Copy source files
    cp "fips-src/$FIPS_VERSION/$CRYPT_SRC_PATH/$MOD.c" "$CRYPT_SRC_PATH" ||
        exit 3
    # Copy header files
    cp "fips-src/$FIPS_VERSION/$CRYPT_INC_PATH/$MOD.h" "$CRYPT_INC_PATH" ||
        exit 4
done

for SRC in "${FIPS_SRCS[@]}"
do
    cp "fips-src/$FIPS_VERSION/$CRYPT_SRC_PATH/$SRC" $CRYPT_SRC_PATH || exit 5
done

for INC in "${FIPS_INCS[@]}"
do
    cp "fips-src/$FIPS_VERSION/$CRYPT_INC_PATH/$INC" $CRYPT_INC_PATH || exit 6
done

if [ "x$CRYPT_OE" != "xORIGIN" ]
then
    # copy the sources and headers from fips-src/<VERSION>/<OE#>/
    if [ -d "fips-src/$FIPS_VERSION/$CRYPT_OE/wolfcrypt" ]; then
        for SRC in "${OE_SRC_MODS[@]}"
        do
            cp "fips-src/$FIPS_VERSION/$CRYPT_OE/$CRYPT_SRC_PATH/$SRC" \
                  "$CRYPT_SRC_PATH" || exit 7
        done
    fi
    if [ -d "fips-src/$FIPS_VERSION/$CRYPT_OE/wolfssl" ]; then
        for HDR in "${OE_HDR_MODS[@]}"
        do
            cp "fips-src/$FIPS_VERSION/$CRYPT_OE/$CRYPT_INC_PATH/$HDR" \
                 "$CRYPT_INC_PATH" || exit 8
        done
    fi
    printf '%s\n' "KALEBS METHOD"
fi

git add wolfcrypt/src wolfssl/wolfcrypt/
# ----------------------------------------------------------------------------#
# run the make test
./autogen.sh
./configure --enable-fips=$FIPS_OPTION
if ! make; then
    echo "fips-check: Make failed. Debris left for analysis."
    exit 9
fi
# ----------------------------------------------------------------------------#
# Update the hash (if applicable)
if [ "x$CAVP_SELFTEST_ONLY" == "xno" ];
then
    NEWHASH=$(./wolfcrypt/test/testwolfcrypt | sed -n 's/hash = \(.*\)/\1/p')
    if [ -n "$NEWHASH" ]; then
        echo "Updating hash to: $NEWHASH"
        sed -i.bak "s/^\".*\";/\"${NEWHASH}\";/" $CRYPT_SRC_PATH/fips_test.c
        make clean
    fi
fi

if ! make test; then
    echo "fips-check: Test failed. Debris left for analysis."
    exit 10
fi
# ----------------------------------------------------------------------------#
# For some OE's there may be conflicts when compiled in the same dir IE:
# cyassl/src/aes.c conflicting with wolfcrypt/src/aes.c, rename if appropriate
if [ ${#FIPS_CONFLICTS[@]} -ne 0 ];
then
    echo "Due to the way this package is compiled by the customer duplicate"
    echo "source file names are an issue, renaming:"
    for FNAME in "${FIPS_CONFLICTS[@]}"
    do
        echo "wolfcrypt/src/$FNAME.c to wolfcrypt/src/wc_$FNAME.c"
        mv "./wolfcrypt/src/$FNAME.c" "./wolfcrypt/src/wc_$FNAME.c"
    done
    echo "Confirming files were renamed..."
    ls -la ./wolfcrypt/src/wc_*.c
fi
# ----------------------------------------------------------------------------#
# Clean up
popd || exit 2
if [ "x$KEEP" == "xno" ];
then
    rm -rf $TEST_DIR
fi
