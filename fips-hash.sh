#!/bin/sh

LC_ALL=C
export LC_ALL

# This script executes the testwolfcrypt binary to report its calculated FIPS
# integrity hash, then it modifies the fips_test.c source code to update the
# expected integrity hash in source.
#
# See fips-hash-offline.sh for a version that calculates the expected FIPS
# integrity hash during the build process on the linked binary. This version is
# suitable for statically linked builds.

# An --enable-linuxkm build has no testwolfcrypt at all; linuxkm/Makefile does
# its own hash update.
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

# testwolfcrypt is a libtool wrapper and reports a missing .libs binary on
# stderr, so judge the run by stdout and leave stderr on the terminal.
TESTOUT=$(./wolfcrypt/test/testwolfcrypt)
TESTRC=$?

# main() in wolfcrypt/test/test.c returns only 0 or 1, so any other status is a
# death before main() returned and nothing it printed can be trusted.
if test "$TESTRC" -ne 0 && test "$TESTRC" -ne 1
then
    echo "fips-hash: testwolfcrypt exited $TESTRC; fips_test.c NOT updated." >&2
    printf '%s\n' "$TESTOUT" >&2
    exit 1
fi

# myFipsCb in wolfcrypt/test/test.c prints at most one message per process, so
# there is only ever one "hash = " line to take.
NEWHASH=$(printf '%s\n' "$TESTOUT" | \
          sed -n 's/^hash = \([0-9A-Fa-f][0-9A-Fa-f]*\).*$/\1/p' | head -1)

if test -z "$NEWHASH"
then
    # Only a FIPS build that ran clean shows the value in source is right. The
    # plain banner is printed by every build, FIPS or not, so it proves nothing.
    case "$TESTOUT" in
        *"FIPS module version in use"*)
            if test "$TESTRC" -eq 0
            then
                echo "fips-hash: in-core hash already matches; fips_test.c unchanged."
                exit 0
            fi
            echo "fips-hash: no hash reported, but testwolfcrypt exited $TESTRC." >&2
            echo "fips-hash: fips_test.c unchanged. Its output:" >&2
            printf '%s\n' "$TESTOUT" >&2
            exit 0
            ;;
        *"wolfSSL version"*)
            echo "fips-hash: no hash and no FIPS module banner; fips_test.c" >&2
            echo "fips-hash: unchanged. Was this configured with --enable-fips?" >&2
            exit 0
            ;;
    esac
    echo "fips-hash: testwolfcrypt printed no banner and no hash," >&2
    echo "fips-hash: so fips_test.c was NOT updated. Its output:" >&2
    printf '%s\n' "$TESTOUT" >&2
    exit 1
fi

if ! cp wolfcrypt/src/fips_test.c wolfcrypt/src/fips_test.c.bak
then
    echo "fips-hash: cannot back up fips_test.c; NOT updated." >&2
    exit 1
fi

# The redirect truncates fips_test.c before sed runs, and the substitution is a
# silent no-op if the literal moved, so confirm the hash landed.
if sed "s/^\".*\";/\"${NEWHASH}\";/" wolfcrypt/src/fips_test.c.bak \
       >wolfcrypt/src/fips_test.c &&
   grep -q "^\"${NEWHASH}\";" wolfcrypt/src/fips_test.c
then
    exit 0
fi

echo "fips-hash: could not write the new hash into fips_test.c." >&2
if ! cp wolfcrypt/src/fips_test.c.bak wolfcrypt/src/fips_test.c
then
    echo "fips-hash: AND the restore failed; fips_test.c is damaged." >&2
    echo "fips-hash: the only good copy is wolfcrypt/src/fips_test.c.bak" >&2
fi
exit 1
