#! /usr/bin/env perl
# SPDX-License-Identifier: BSD-3-Clause
#
# Cross-checks the Perl NEON encoders in neon_encode.pl against
# arm-linux-gnueabihf-as. Reads NEON GAS lines on stdin (one per
# line); for each, computes the Perl encoding and the arm-as
# encoding and reports any mismatch.
#
# Usage:
#   perl neon_encode_test.pl <neon_lines.txt
#
# A typical run:
#   grep -hoE '^\s*v[a-z][a-z0-9.]*[^@]*' /tmp/chacha-neon.S \
#     | sed 's/^[ \t]*//; s/[ \t]*$//' \
#     | sort -u \
#     | perl neon_encode_test.pl
#
# Exit 0 if all encodings match (or all unhandled lines are
# explicitly skipped); non-zero on the first encoding mismatch.

use strict;
use warnings;
use File::Temp qw/tempfile/;
use FindBin;
require "$FindBin::Bin/neon_encode.pl";

sub asm_encode_batch {
    my @lines = @_;
    my ($sf, $sp) = tempfile("nv-XXXX", SUFFIX => ".s", TMPDIR => 1);
    my ($of, $op) = tempfile("nv-XXXX", SUFFIX => ".o", TMPDIR => 1);
    my ($bf, $bp) = tempfile("nv-XXXX", SUFFIX => ".bin", TMPDIR => 1);
    close $of; close $bf;
    print $sf ".syntax unified\n.arch armv7-a\n.fpu neon\n.code 32\n";
    for my $l (@lines) { print $sf "$l\n"; }
    close $sf;
    system("arm-linux-gnueabihf-as", "-mfpu=neon", "-march=armv7-a",
           "-o", $op, $sp) == 0
        or die "arm-as failed; input at $sp\n";
    system("arm-linux-gnueabihf-objcopy", "-O", "binary",
           "--only-section=.text", $op, $bp) == 0
        or die "objcopy failed\n";
    open my $fh, "<:raw", $bp or die;
    my $buf;
    read $fh, $buf, -s $bp;
    close $fh;
    unlink $sp, $op, $bp;
    my @words = unpack("V*", $buf);
    return @words;
}

my @lines;
while (my $l = <STDIN>) {
    chomp $l;
    $l =~ s/^\s+|\s+$//g;
    next unless length $l;
    next if $l =~ /^[#@\.]/;
    push @lines, $l;
}

my @asm = asm_encode_batch(@lines);
if (@asm != @lines) {
    die sprintf("arm-as produced %d words for %d lines\n",
                scalar @asm, scalar @lines);
}

my $ok       = 0;
my $mismatch = 0;
my $skipped  = 0;
for (my $i = 0; $i < @lines; $i++) {
    my $line = $lines[$i];
    my $want = $asm[$i];
    my $got  = eval { encode_neon($line) };
    if ($@) {
        $skipped++;
        next;
    }
    if ($got == $want) {
        $ok++;
    } else {
        $mismatch++;
        printf STDERR "MISMATCH: %-40s perl=0x%08x asm=0x%08x\n",
            $line, $got, $want;
    }
}

printf "ok=%d  mismatch=%d  skipped(no encoder)=%d\n",
    $ok, $mismatch, $skipped;
exit($mismatch ? 1 : 0);
