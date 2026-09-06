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
# still runs, printing its own error to stderr, so capture both streams.
TESTOUT=$(./wolfcrypt/test/testwolfcrypt 2>&1)
TESTRC=$?

# A run that reached main() prints the banner (hash already matched) or a hash
# line (hash needs replacing). Neither means it never got that far, and a stale
# hash left in place makes every FIPS call return IN_CORE_FIPS_E (-203).
case "$TESTOUT" in
    *"wolfSSL version"*)
        ;;
    *hash\ =\ [0-9A-Fa-f]*)
        # main() in wolfcrypt/test/test.c returns 0 or 1; anything else died
        # before it returned.
        if test "$TESTRC" -ne 0 && test "$TESTRC" -ne 1
        then
            echo "fips-hash: testwolfcrypt exited $TESTRC, so it died before" >&2
            echo "fips-hash: main() returned; fips_test.c NOT updated." >&2
            printf '%s\n' "$TESTOUT" >&2
            exit 1
        fi
        ;;
    *)
        echo "fips-hash: testwolfcrypt did not run; fips_test.c NOT updated." >&2
        echo "fips-hash: the module would fail with -203." >&2
        printf '%s\n' "$TESTOUT" >&2
        exit 1
        ;;
esac

# Take the hash exactly as long as reported: the in core digest is SHA-256 (64
# hex) up to FIPS v6.0.0 and SHA-512 (128 hex) from v7.0.0 on.
NEWHASH=$(printf '%s\n' "$TESTOUT" | \
          sed -n 's/^hash = \([0-9A-Fa-f][0-9A-Fa-f]*\).*$/\1/p' | head -1)

# A hash is printed only when the in-core check fails, so none means the value
# already in fips_test.c is correct.
if test -z "$NEWHASH"
then
    echo "fips-hash: in-core hash already matches; fips_test.c unchanged."
    exit 0
fi

cp wolfcrypt/src/fips_test.c wolfcrypt/src/fips_test.c.bak
sed "s/^\".*\";/\"${NEWHASH}\";/" wolfcrypt/src/fips_test.c.bak >wolfcrypt/src/fips_test.c
