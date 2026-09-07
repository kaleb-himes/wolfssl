#!/bin/sh

# This script executes the testwolfcrypt binary to report its calculated FIPS
# integrity hash, then it modifies the fips_test.c source code to update the
# expected integrity hash in source.
#
# See fips-hash-offline.sh for a version that calculates the expected FIPS
# integrity hash during the build process on the linked binary. This version is
# suitable for statically linked builds.

# An --enable-linuxkm build has no testwolfcrypt at all; linuxkm/Makefile runs
# its own hash update. This script is for userspace builds.
if test ! -x ./wolfcrypt/test/testwolfcrypt
then
    echo "fips-hash: wolfCrypt test missing"
    exit 1
fi

if test ! -s ./wolfcrypt/src/fips_test.c
then
    echo "fips-hash: fips_test.c missing"
    exit 1
fi

# testwolfcrypt is a libtool wrapper script. With .libs/testwolfcrypt missing it
# prints its own error to stderr and exits 1, so stdout alone says whether the
# test really ran. Leave stderr on the terminal where the build log gets it.
TESTOUT=$(./wolfcrypt/test/testwolfcrypt)
TESTRC=$?

# The hash line is printed only when the in-core check fails, which is what this
# script is for. Take it exactly as long as reported: the digest is SHA-256 (64
# hex) up to FIPS v6.0.0 and SHA-512 (128 hex) from v7.0.0 on.
NEWHASH=$(printf '%s\n' "$TESTOUT" | \
          sed -n 's/^hash = \([0-9A-Fa-f][0-9A-Fa-f]*\).*$/\1/p' | head -1)

if test -n "$NEWHASH"
then
    # main() in wolfcrypt/test/test.c returns 0 or 1; anything else means it
    # died before main() returned, so the hash it printed is not trustworthy.
    if test "$TESTRC" -ne 0 && test "$TESTRC" -ne 1
    then
        echo "fips-hash: testwolfcrypt exited $TESTRC, so it died before" >&2
        echo "fips-hash: main() returned; fips_test.c NOT updated." >&2
        exit 1
    fi
    cp wolfcrypt/src/fips_test.c wolfcrypt/src/fips_test.c.bak
    sed "s/^\".*\";/\"${NEWHASH}\";/" wolfcrypt/src/fips_test.c.bak \
        >wolfcrypt/src/fips_test.c
    exit 0
fi

# No hash line. The banner means it ran and the hash already matched; nothing at
# all means it never ran, and keeping the stale hash would make every FIPS call
# return IN_CORE_FIPS_E (-203).
case "$TESTOUT" in
    *"wolfSSL version"*)
        echo "fips-hash: in-core hash already matches; fips_test.c unchanged."
        ;;
    *)
        echo "fips-hash: testwolfcrypt did not run; fips_test.c NOT updated." >&2
        echo "fips-hash: the module would fail with -203." >&2
        exit 1
        ;;
esac
