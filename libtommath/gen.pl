#!/usr/bin/perl -w
#
# Generates a "single file" you can use to quickly
# add the whole source without any makefile troubles
#
use strict;

open( OUT, ">mpi.c" ) or die "Couldn't open mpi.c for writing: $!";
foreach my $filename (glob "bn_*.c") {
   open( SRC, "<$filename" ) or die "Couldn't open $filename for reading: $!";
   print OUT "/* Start: $filename */\n";
   print OUT qq[#line 0 "$filename"\n];
   print OUT while <SRC>;
   print OUT "\n/* End: $filename */\n\n";
   close SRC or die "Error closing $filename after reading: $!";
}
print OUT "\b/* EOF */\n";
close OUT or die "Error closing mpi.c after writing: $!";