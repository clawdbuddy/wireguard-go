#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
#
# Regenerate Plan 9 ARM assembly from upstream CryptoGAMS Perl. Run
# from anywhere:
#
#     ./tsasm/arm/regen/regen.sh
#
# The CryptoGAMS .pl files are NOT vendored. They are downloaded on
# demand into a local .cache/ directory (gitignored) and verified
# against the SHA256 sums recorded below. To bump upstream:
#
#   1. Update CRYPTOGAMS_SHA to the new commit.
#   2. Update each fetch's SHA256 to match the new content.
#   3. Run this script and review the resulting .s diff.
#
# Required tools: perl, cpp, curl, sh, sha256sum,
# arm-linux-gnueabihf-as, arm-linux-gnueabihf-objcopy (the last two
# only fill a few pure-Perl-encoder gaps; eventual goal is full
# Perl coverage so we drop the cross-as dependency).
set -eu

cd "$(dirname "$0")"

# Pinned upstream commit. https://github.com/tailscale/cryptogams is
# a Tailscale-hosted mirror of github.com/dot-asm/cryptogams (Andy
# Polyakov's CryptoGAMS distribution) so we don't depend on a
# third-party repo staying available.
CRYPTOGAMS_SHA=680f98c
BASE=https://raw.githubusercontent.com/tailscale/cryptogams/${CRYPTOGAMS_SHA}

mkdir -p .cache

fetch() {
    src=$1; want_sha=$2
    dest=.cache/$(basename "$src")
    if [ -f "$dest" ]; then
        got=$(sha256sum < "$dest" | cut -d' ' -f1)
        if [ "$got" = "$want_sha" ]; then
            return
        fi
    fi
    echo "fetching $src"
    curl -fsSL "$BASE/$src" -o "$dest"
    got=$(sha256sum < "$dest" | cut -d' ' -f1)
    if [ "$got" != "$want_sha" ]; then
        echo "checksum mismatch for $src:" >&2
        echo "  want $want_sha" >&2
        echo "  got  $got" >&2
        exit 1
    fi
}

fetch arm/chacha-armv4.pl   3597151ed599842e10fee64a3ad13a46f1cce76ba72eac39259d20732218f8ec
fetch arm/poly1305-armv4.pl 96a3789f4e7881b04e7f74b3b1e5ed25d31483c65d6b3d85622a87c1c20e8463
fetch arm/arm-xlate.pl      f8e13d5fe5498589ebca86b49a85993c4b72037a13e61073af8314fef7c49b4d

# 1. Run upstream Perl on each algorithm script to produce GAS-syntax
#    .S files. arm-xlate.pl needs to be next to chacha-armv4.pl /
#    poly1305-armv4.pl because they `use` it relative to their own
#    location.
perl .cache/chacha-armv4.pl   linux32 .cache/chacha-armv4.S
perl .cache/poly1305-armv4.pl linux32 .cache/poly1305-armv4.S

# 2. CPP-preprocess (strip CPP directives, expand __ARM_ARCH__ guards)
#    then run plan9-xlate.pl to emit Plan 9 ARM assembly. arm_arch.h
#    next to this script is our minimal stub; the upstream version is
#    much larger and drags in machinery we don't need (architecture
#    detection macros that we supply directly via -D).
common_cpp_flags="-P -I . -D__ARM_ARCH__=6 -D__ARM_MAX_ARCH__=6"

# poly1305: emits poly1305_init / poly1305_blocks / poly1305_emit.
cpp $common_cpp_flags .cache/poly1305-armv4.S \
    | perl plan9-xlate.pl \
    > ../poly1305/poly1305_arm.s

cpp $common_cpp_flags .cache/chacha-armv4.S \
    | perl plan9-xlate.pl \
    > ../chacha20/chacha20_arm.s

# Same scripts at __ARM_MAX_ARCH__=7 to pick up the NEON paths.
# We emit only the NEON entry points and concatenate them onto the
# scalar .s files (sigma/one/rot8 etc. data sections live in the
# scalar half so we don't redefine them here).
neon_cpp_flags="-P -I . -D__ARM_ARCH__=7 -D__ARM_MAX_ARCH__=7"

# Strip the leading boilerplate (the `// Code generated...` banner and
# the `#include` lines) and the trailing DATA/GLOBL blocks: those are
# already in the scalar half. Keeping just the TEXT bodies gives a
# clean append-only delta.
strip_boilerplate_and_data() {
    awk '
        /^TEXT/ { in_text = 1 }
        /^DATA / { in_text = 0 }
        /^GLOBL / { in_text = 0; next }
        in_text { print }
    '
}

cpp $neon_cpp_flags .cache/poly1305-armv4.S \
    | perl plan9-xlate.pl --only='^poly1305_(init|blocks)_neon$' \
    | strip_boilerplate_and_data \
    >> ../poly1305/poly1305_arm.s

cpp $neon_cpp_flags .cache/chacha-armv4.S \
    | perl plan9-xlate.pl --only='^ChaCha20_neon$' \
    | strip_boilerplate_and_data \
    >> ../chacha20/chacha20_arm.s

echo "Regenerated:"
echo "  tsasm/arm/poly1305/poly1305_arm.s   (scalar + NEON)"
echo "  tsasm/arm/chacha20/chacha20_arm.s   (scalar + NEON)"
