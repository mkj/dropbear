#!/usr/bin/env perl

use strict;
use warnings;

use Getopt::Long;
use File::Find 'find';
use File::Basename 'basename';
use File::Glob 'bsd_glob';

sub read_file {
  my $f = shift;
  open my $fh, "<", $f or die "FATAL: read_rawfile() cannot open file '$f': $!";
  binmode $fh;
  return do { local $/; <$fh> };
}

sub write_file {
  my ($f, $data) = @_;
  die "FATAL: write_file() no data" unless defined $data;
  open my $fh, ">", $f or die "FATAL: write_file() cannot open file '$f': $!";
  binmode $fh;
  print $fh $data or die "FATAL: write_file() cannot write to '$f': $!";
  close $fh or die "FATAL: write_file() cannot close '$f': $!";
  return;
}

sub check_source {
  my @all_files = (
        bsd_glob("makefile*"),
        bsd_glob("*.{h,c,sh,pl}"),
        bsd_glob("*/*.{h,c,sh,pl}"),
  );

  my $fails = 0;
  for my $file (sort @all_files) {
    my $troubles = {};
    my $lineno = 1;
    my $content = read_file($file);
    push @{$troubles->{crlf_line_end}}, '?' if $content =~ /\r/;
    for my $l (split /\n/, $content) {
      push @{$troubles->{merge_conflict}},     $lineno if $l =~ /^(<<<<<<<|=======|>>>>>>>)([^<=>]|$)/;
      push @{$troubles->{trailing_space}},     $lineno if $l =~ / $/;
      push @{$troubles->{tab}},                $lineno if $l =~ /\t/ && basename($file) !~ /^makefile/i;
      push @{$troubles->{non_ascii_char}},     $lineno if $l =~ /[^[:ascii:]]/;
      push @{$troubles->{cpp_comment}},        $lineno if $file =~ /\.(c|h)$/ && ($l =~ /\s\/\// || $l =~ /\/\/\s/);
      # we prefer using XMALLOC, XFREE, XREALLOC, XCALLOC ...
      push @{$troubles->{unwanted_malloc}},    $lineno if $file =~ /^[^\/]+\.c$/ && $l =~ /\bmalloc\s*\(/;
      push @{$troubles->{unwanted_realloc}},   $lineno if $file =~ /^[^\/]+\.c$/ && $l =~ /\brealloc\s*\(/;
      push @{$troubles->{unwanted_calloc}},    $lineno if $file =~ /^[^\/]+\.c$/ && $l =~ /\bcalloc\s*\(/;
      push @{$troubles->{unwanted_free}},      $lineno if $file =~ /^[^\/]+\.c$/ && $l =~ /\bfree\s*\(/;
      # and we probably want to also avoid the following
      push @{$troubles->{unwanted_memcpy}},    $lineno if $file =~ /^[^\/]+\.c$/ && $l =~ /\bmemcpy\s*\(/;
      push @{$troubles->{unwanted_memset}},    $lineno if $file =~ /^[^\/]+\.c$/ && $l =~ /\bmemset\s*\(/;
      push @{$troubles->{unwanted_memcpy}},    $lineno if $file =~ /^[^\/]+\.c$/ && $l =~ /\bmemcpy\s*\(/;
      push @{$troubles->{unwanted_memmove}},   $lineno if $file =~ /^[^\/]+\.c$/ && $l =~ /\bmemmove\s*\(/;
      push @{$troubles->{unwanted_memcmp}},    $lineno if $file =~ /^[^\/]+\.c$/ && $l =~ /\bmemcmp\s*\(/;
      push @{$troubles->{unwanted_strcmp}},    $lineno if $file =~ /^[^\/]+\.c$/ && $l =~ /\bstrcmp\s*\(/;
      push @{$troubles->{unwanted_strcpy}},    $lineno if $file =~ /^[^\/]+\.c$/ && $l =~ /\bstrcpy\s*\(/;
      push @{$troubles->{unwanted_strncpy}},   $lineno if $file =~ /^[^\/]+\.c$/ && $l =~ /\bstrncpy\s*\(/;
      push @{$troubles->{unwanted_clock}},     $lineno if $file =~ /^[^\/]+\.c$/ && $l =~ /\bclock\s*\(/;
      push @{$troubles->{unwanted_qsort}},     $lineno if $file =~ /^[^\/]+\.c$/ && $l =~ /\bqsort\s*\(/;
      push @{$troubles->{sizeof_no_brackets}}, $lineno if $file =~ /^[^\/]+\.c$/ && $l =~ /\bsizeof\s*[^\(]/;
      if ($file =~ m|^[^\/]+\.c$| && $l =~ /^static(\s+[a-zA-Z0-9_]+)+\s+([a-zA-Z0-9_]+)\s*\(/) {
        my $funcname = $2;
        # static functions should start with s_
        push @{$troubles->{staticfunc_name}}, "$lineno($funcname)" if $funcname !~ /^s_/;
      }
      $lineno++;
    }
    for my $k (sort keys %$troubles) {
      warn "[$k] $file line:" . join(",", @{$troubles->{$k}}) . "\n";
      $fails++;
    }
  }

  warn( $fails > 0 ? "check-source:    FAIL $fails\n" : "check-source:    PASS\n" );
  return $fails;
}

sub check_comments {
  my $fails = 0;
  my $first_comment = <<'MARKER';
/* LibTomMath, multiple-precision integer library -- Tom St Denis
 *
 * LibTomMath is a library that provides multiple-precision
 * integer arithmetic as well as number theoretic functionality.
 *
 * The library was designed directly after the MPI library by
 * Michael Fromberger but has been written from scratch with
 * additional optimizations in place.
 *
 * SPDX-License-Identifier: Unlicense
 */
MARKER
  my $last_comment = <<'MARKER';
/* ref:         HEAD -> master, tag: v1.1.0 */
/* git commit:  08549ad6bc8b0cede0b357a9c341c5c6473a9c55 */
/* commit time: 2019-01-28 20:32:32 +0100 */
MARKER
  #my @all_files = (bsd_glob("*.{h,c}"), bsd_glob("*/*.{h,c}"));
  my @all_files = (bsd_glob("*.{h,c}"));
  for my $f (@all_files) {
    my $txt = read_file($f);
    if ($txt !~ /\Q$first_comment\E/s) {
      warn "[first_comment] $f\n";
      $fails++;
    }
    if ($txt !~ /\Q$last_comment\E\s*$/s) {
      warn "[last_comment] $f\n";
      $fails++;
    }
  }
  warn( $fails > 0 ? "check-comments:  FAIL $fails\n" : "check-comments:  PASS\n" );
  return $fails;
}

sub prepare_variable {
  my ($varname, @list) = @_;
  my $output = "$varname=";
  my $len = length($output);
  foreach my $obj (sort @list) {
    $len = $len + length $obj;
    $obj =~ s/\*/\$/;
    if ($len > 100) {
      $output .= "\\\n";
      $len = length $obj;
    }
    $output .= $obj . ' ';
  }
  $output =~ s/ $//;
  return $output;
}

sub prepare_msvc_files_xml {
  my ($all, $exclude_re, $targets) = @_;
  my $last = [];
  my $depth = 2;

  # sort files in the same order as visual studio (ugly, I know)
  my @parts = ();
  for my $orig (@$all) {
    my $p = $orig;
    $p =~ s|/|/~|g;
    $p =~ s|/~([^/]+)$|/$1|g;
    my @l = map { sprintf "% -99s", $_ } split /\//, $p;
    push @parts, [ $orig, join(':', @l) ];
  }
  my @sorted = map { $_->[0] } sort { $a->[1] cmp $b->[1] } @parts;

  my $files = "<Files>\r\n";
  for my $full (@sorted) {
    my @items = split /\//, $full; # split by '/'
    $full =~ s|/|\\|g;             # replace '/' bt '\'
    shift @items; # drop first one (src)
    pop @items;   # drop last one (filename.ext)
    my $current = \@items;
    if (join(':', @$current) ne join(':', @$last)) {
      my $common = 0;
      $common++ while ($last->[$common] && $current->[$common] && $last->[$common] eq $current->[$common]);
      my $back = @$last - $common;
      if ($back > 0) {
        $files .= ("\t" x --$depth) . "</Filter>\r\n" for (1..$back);
      }
      my $fwd = [ @$current ]; splice(@$fwd, 0, $common);
      for my $i (0..scalar(@$fwd) - 1) {
        $files .= ("\t" x $depth) . "<Filter\r\n";
        $files .= ("\t" x $depth) . "\tName=\"$fwd->[$i]\"\r\n";
        $files .= ("\t" x $depth) . "\t>\r\n";
        $depth++;
      }
      $last = $current;
    }
    $files .= ("\t" x $depth) . "<File\r\n";
    $files .= ("\t" x $depth) . "\tRelativePath=\"$full\"\r\n";
    $files .= ("\t" x $depth) . "\t>\r\n";
    if ($full =~ $exclude_re) {
      for (@$targets) {
        $files .= ("\t" x $depth) . "\t<FileConfiguration\r\n";
        $files .= ("\t" x $depth) . "\t\tName=\"$_\"\r\n";
        $files .= ("\t" x $depth) . "\t\tExcludedFromBuild=\"true\"\r\n";
        $files .= ("\t" x $depth) . "\t\t>\r\n";
        $files .= ("\t" x $depth) . "\t\t<Tool\r\n";
        $files .= ("\t" x $depth) . "\t\t\tName=\"VCCLCompilerTool\"\r\n";
        $files .= ("\t" x $depth) . "\t\t\tAdditionalIncludeDirectories=\"\"\r\n";
        $files .= ("\t" x $depth) . "\t\t\tPreprocessorDefinitions=\"\"\r\n";
        $files .= ("\t" x $depth) . "\t\t/>\r\n";
        $files .= ("\t" x $depth) . "\t</FileConfiguration>\r\n";
      }
    }
    $files .= ("\t" x $depth) . "</File>\r\n";
  }
  $files .= ("\t" x --$depth) . "</Filter>\r\n" for (@$last);
  $files .= "\t</Files>";
  return $files;
}

sub patch_file {
  my ($content, @variables) = @_;
  for my $v (@variables) {
    if ($v =~ /^([A-Z0-9_]+)\s*=.*$/si) {
      my $name = $1;
      $content =~ s/\n\Q$name\E\b.*?[^\\]\n/\n$v\n/s;
    }
    else {
      die "patch_file failed: " . substr($v, 0, 30) . "..";
    }
  }
  return $content;
}

sub version_from_tomcrypt_h {
  my $h = read_file(shift);
  if ($h =~ /\n#define\s*SCRYPT\s*"([0-9]+)\.([0-9]+)\.([0-9]+)(.*)"/s) {
    return "VERSION_PC=$1.$2.$3", "VERSION_LT=1:1", "VERSION=$1.$2.$3$4", "PROJECT_NUMBER=$1.$2.$3$4";
  }
  else {
    die "#define SCRYPT not found in tomcrypt.h";
  }
}

sub process_makefiles {
  my $write = shift;
  my $changed_count = 0;
  my @o = map { my $x = $_; $x =~ s/\.c$/.o/; $x } bsd_glob("*.c");
  my @all = bsd_glob("*.{c,h}");

  my $var_o = prepare_variable("OBJECTS", @o);
  (my $var_obj = $var_o) =~ s/\.o\b/.obj/sg;

  # update OBJECTS + HEADERS in makefile*
  for my $m (qw/ Makefile.in /) {
    my $old = read_file($m);
    my $new = $m eq 'makefile.msvc' ? patch_file($old, $var_obj)
                                    : patch_file($old, $var_o);
    if ($old ne $new) {
      write_file($m, $new) if $write;
      warn "changed: $m\n";
      $changed_count++;
    }
  }

  if ($write) {
    return 0; # no failures
  }
  else {
    warn( $changed_count > 0 ? "check-makefiles: FAIL $changed_count\n" : "check-makefiles: PASS\n" );
    return $changed_count;
  }
}

sub die_usage {
  die <<"MARKER";
usage: $0 -s   OR   $0 --check-source
       $0 -o   OR   $0 --check-comments
       $0 -m   OR   $0 --check-makefiles
       $0 -a   OR   $0 --check-all
       $0 -u   OR   $0 --update-makefiles
MARKER
}

GetOptions( "s|check-source"        => \my $check_source,
            "o|check-comments"      => \my $check_comments,
            "m|check-makefiles"     => \my $check_makefiles,
            "a|check-all"           => \my $check_all,
            "u|update-makefiles"    => \my $update_makefiles,
            "h|help"                => \my $help
          ) or die_usage;

my $failure;
$failure ||= check_source()       if $check_all || $check_source;
$failure ||= check_comments()     if $check_all || $check_comments;
$failure ||= process_makefiles(0) if $check_all || $check_makefiles;
$failure ||= process_makefiles(1) if $update_makefiles;

die_usage unless defined $failure;
exit $failure ? 1 : 0;

# ref:         HEAD -> master, tag: v1.1.0
# git commit:  08549ad6bc8b0cede0b357a9c341c5c6473a9c55
# commit time: 2019-01-28 20:32:32 +0100
