#!/usr/bin/perl
#
# Generates a makefile based on user input
#
# Tom St Denis, tomstdenis@yahoo.com, http://tom.iahu.ca

@settings = (
   "CC,Compiler,gcc",
   "AR,Archiver,ar",
   "LD,Linker,ld",
   "CFLAGS,Optimizations,-Os",
   "CFLAGS,Warnings,-Wall -Wsign-compare -W -Wno-unused -Werror",
   "CFLAGS,Include Paths,-I./",
   "CFLAGS,Other compiler options,",
   "CFLAGS,XMALLOC,-DXMALLOC=malloc",
   "CFLAGS,XREALLOC,-DXREALLOC=realloc",
   "CFLAGS,XCALLOC,-DXCALLOC=calloc",
   "CFLAGS,XFREE,-DXFREE=free",
   "CFLAGS,XCLOCK,-DXCLOCK=clock",
   "CFLAGS,XCLOCKS_PER_SEC,-DXCLOCKS_PER_SEC=CLOCKS_PER_SEC",
);

@opts = (
   "SMALL_CODE,Use small code where possible (slower code),y",
   "NO_FILE,Avoid file I/O calls,n",
   "CLEAN_STACK,Clean the stack within functions,n",
   "LTC_TEST,Include Test Vector Routines,y",

   "BLOWFISH,Include Blowfish block cipher,y",
   "RC2,Include RC2 block cipher,y",
   "RC5,Include RC5 block cipher,y",
   "RC6,Include RC6 block cipher,y",
   "SAFERP,Include Safer+ block cipher,y",
   "SAFER,Include Safer-64 block ciphers,n",
   "RIJNDAEL,Include Rijndael (AES) block cipher,y",
   "XTEA,Include XTEA block cipher,y",
   "TWOFISH,Include Twofish block cipher (default: fast),y",
   "TWOFISH_SMALL,Use a low ram variant of Twofish (slow cipher+keyschedule!),n",
   "TWOFISH_TABLES,Use precomputed tables (fast cipher and faster keychedule but adds ~3.3KB to the size),y",
   "TWOFISH_ALL_TABLES,Speed up the key schedule a little (adds ~8KB ontop of TWOFISH_TABLES to the size),n",
   "DES,Include DES and 3DES block ciphers,y",
   "CAST5,Include CAST5 (aka CAST-128) block cipher,y",
   "NOEKEON,Include Noekeon block cipher,y",
   "SKIPJACK,Include Skipjack block cipher,y",

   "CFB,Include CFB block mode of operation,y",
   "OFB,Include OFB block mode of operation,y",
   "ECB,Include ECB block mode of operation,y",
   "CBC,Include CBC block mode of operation,y",
   "CTR,Include CTR block mode of operation,y",

   "WHIRLPOOL,Include WHIRLPOOL 512-bit one-way hash,y",
   "SHA512,Include SHA512 one-way hash,y",
   "SHA384,Include SHA384 one-way hash (requires SHA512),y",
   "SHA256,Include SHA256 one-way hash,y",
   "SHA224,Include SHA224 one-way hash (requires SHA256),y",
   "TIGER,Include TIGER one-way hash,y",
   "SHA1,Include SHA1 one-way hash,y",
   "MD5,Include MD5 one-way hash,y",
   "MD4,Include MD4 one-way hash,y",
   "MD2,Include MD2 one-way hash,y",
   "RIPEMD128,Include RIPEMD-128 one-way hash,y",
   "RIPEMD160,Include RIPEMD-160 one-way hash,y",
   "HMAC,Include Hash based Message Authentication Support,y",
   "OMAC,Include OMAC1 Message Authentication Support,y",
   "PMAC,Include PMAC Message Authentication Support,y",
   "EAX_MODE,Include EAX Encrypt-and-Authenticate Support,y",
   "OCB_MODE,Include OCB Encrypt-and-Authenticate Support,y",

   "BASE64,Include Base64 encoding support,y",

   "YARROW,Include Yarrow PRNG,y",
   "SPRNG,Include Secure PRNG base on RNG code,y",
   "RC4,Include RC4 PRNG,y",
   "DEVRANDOM,Use /dev/random or /dev/urandom if available?,y",
   "TRY_URANDOM_FIRST,Try /dev/urandom before /dev/random?,n",

   "MRSA,Include RSA public key support,y",
   "MDSA,Include DSA public key support,y",
   "MDH,Include Diffie-Hellman (over Z/pZ) public key support,y",
   "MECC,Include Eliptic Curve public key crypto support,y",
   "KR,Include Keyring support (groups all three PK systems),n",
   
   "DH768,768-bit DH key support,y",
   "DH1024,1024-bit DH key support,y",
   "DH1280,1280-bit DH key support,y",
   "DH1536,1536-bit DH key support,y",
   "DH1792,1792-bit DH key support,y",
   "DH2048,2048-bit DH key support,y",
   "DH2560,2560-bit DH key support,y",
   "DH3072,3072-bit DH key support,y",
   "DH4096,4096-bit DH key support,y",
   
   "ECC160,160-bit ECC key support,y",
   "ECC192,192-bit ECC key support,y",
   "ECC224,224-bit ECC key support,y",
   "ECC256,256-bit ECC key support,y",
   "ECC384,384-bit ECC key support,y",
   "ECC521,521-bit ECC key support,y",
   
   "GF,Include GF(2^w) math support (not used internally),n",
   
   "MPI,Include MPI big integer math support (required by the public key code),y",
);

# scan for switches and make variables
for (@settings) {
   @m = split(",", $_);
   print "@m[1]: [@m[2]] ";
   $r = <>; $r = @m[2] if ($r eq "\n");
   chomp($r);
   @vars{@m[0]} = @vars{@m[0]} . $r . " ";
}

# scan for build flags
for (@opts) {
   @m = split(",", $_);
   print "@m[1]: [@m[2]]";
   $r = <>;  @vars{'CFLAGS'} = @vars{'CFLAGS'} . "-D" . $m[0] . " " if (($r eq "y\n") || ($r eq "\n" && @m[2] eq "y"));
}   

# write header

open(OUT,">mycrypt_custom.h");
print OUT "/* This header is meant to be included before mycrypt.h in projects where\n";
print OUT " * you don't want to throw all the defines in a makefile. \n";
print OUT " */\n\n#ifndef MYCRYPT_CUSTOM_H_\n#define MYCRYPT_CUSTOM_H_\n\n#ifdef CRYPT\n\t#error mycrypt_custom.h should be included before mycrypt.h\n#endif\n\n";

@m = split(" ", @vars{'CFLAGS'});
for (@m) {
    if ($_ =~ /^-D/) {
       $_ =~ s/-D//;
       $_ =~ s/=/" "/ge;
       print OUT "#define $_\n";
    }
}

print OUT "\n\n#include <mycrypt.h>\n\n#endif\n\n";
close OUT;
       
print "\n\nmycrypt_custom.h generated.\n";

open(OUT,">makefile.out");
print OUT "#makefile generated with config.pl\n#\n#Tom St Denis (tomstdenis\@yahoo.com, http://tom.iahu.ca) \n\n";

# output unique vars first
@vars{'CFLAGS'} =~ s/-D.+ /""/ge;

for (@settings) {
   @m = split(",", $_);
   print OUT "@m[0] = @vars{@m[0]}\n"   if (@vars{@m[0]} ne "" && @m[0] ne "CFLAGS");
   print OUT "CFLAGS += @vars{@m[0]}\n" if (@vars{@m[0]} ne "" && @m[0] eq "CFLAGS");
   @vars{@m[0]} = "";
}

# output objects
print OUT "\ndefault: library\n\n";
print OUT "OBJECTS = keyring.o gf.o mem.o sprng.o ecc.o base64.o dh.o rsa.o bits.o yarrow.o cfb.o ofb.o ecb.o ctr.o cbc.o hash.o tiger.o sha1.o md5.o md4.o md2.o sha256.o sha512.o xtea.o aes.o des.o safer_tab.o safer.o saferp.o rc4.o rc2.o rc6.o rc5.o cast5.o noekeon.o blowfish.o crypt.o mpi.o prime.o twofish.o packet.o hmac.o strings.o rmd128.o rmd160.o skipjack.o omac.o dsa.o eax.o ocb.o pmac.o whirl.o\n\n";

# some depends
print OUT "rsa.o: rsa_sys.c\ndh.o: dh_sys.c\necc.o: ecc_sys.c\naes.o: aes.c aes_tab.c\ntwofish.o: twofish.c twofish_tab.c\nsha512.o: sha384.c sha512.c\nsha256.o: sha256.c sha224.c\n\n";

# targets
print OUT "library: \$(OBJECTS)\n\t \$(AR) r libtomcrypt.a \$(OBJECTS)\n\t ranlib libtomcrypt.a\n\n";
print OUT "clean:\n\trm -f \$(OBJECTS) libtomcrypt.a \n\n";

close OUT;

print "makefile.out generated.\n";

print "\nNow use makefile.out to build the library, e.g. `make -f makefile.out'\n";
print "In your project just include mycrypt_custom.h (you don't have to include mycrypt.h \n";
print "but if you do make sure mycrypt_custom.h appears first) your settings should be intact.\n";
