# MAKEFILE for linux GCC
#
# Tom St Denis
# Modified by Clay Culver
#
# NOTE: This should later be replaced by autoconf/automake scripts, but for
# the time being this is actually pretty clean. The only ugly part is
# handling CFLAGS so that the x86 specific optimizations don't break
# a build. This is easy to remedy though, for those that have problems.

# The version
VERSION=0.82

#ch1-01-1
# Compiler and Linker Names
CC=gcc
LD=ld

# Archiver [makes .a files]
AR=ar
ARFLAGS=r
#ch1-01-1

#ch1-01-3
# Compilation flags. Note the += does not write over the user's CFLAGS!
CFLAGS += -c -I./ -Wall -Wsign-compare -W -Wno-unused -Werror

# optimize for SPEED
#CFLAGS += -O3 -funroll-loops

# optimize for SIZE
CFLAGS += -Os

# compile for DEBUGGING
#CFLAGS += -g3
#ch1-01-3

#These flags control how the library gets built.

#Output filenames for various targets.
LIBNAME=libtomcrypt.a
TEST=test
HASH=hashsum
CRYPT=encrypt
SMALL=small

#LIBPATH-The directory for libtomcrypt to be installed to.
#INCPATH-The directory to install the header files for libtomcrypt.
#DATAPATH-The directory to install the pdf docs.
DESTDIR=
LIBPATH=/usr/lib
INCPATH=/usr/include
DATAPATH=/usr/share/doc/libtomcrypt/pdf

#List of objects to compile.
OBJECTS=keyring.o gf.o mem.o sprng.o ecc.o base64.o dh.o rsa.o \
bits.o yarrow.o cfb.o ofb.o ecb.o ctr.o cbc.o hash.o tiger.o sha1.o \
md5.o md4.o md2.o sha256.o sha512.o xtea.o aes.o serpent.o des.o \
safer_tab.o safer.o safer+.o rc4.o rc2.o rc6.o rc5.o cast5.o noekeon.o blowfish.o crypt.o \
ampi.o mpi.o prime.o twofish.o packet.o hmac.o strings.o

TESTOBJECTS=demos/test.o
HASHOBJECTS=demos/hashsum.o
CRYPTOBJECTS=demos/encrypt.o
SMALLOBJECTS=demos/small.o

#Files left over from making the crypt.pdf.
LEFTOVERS=*.dvi *.log *.aux *.toc *.idx *.ilg *.ind

#Compressed filenames
COMPRESSED=crypt.tar.bz2 crypt.zip crypt.tar.gz

#Header files used by libtomcrypt.
HEADERS=mpi.h mycrypt_cfg.h mycrypt_gf.h mycrypt_kr.h \
mycrypt_misc.h  mycrypt_prng.h mycrypt_cipher.h  mycrypt_hash.h \
mycrypt_macros.h  mycrypt_pk.h mycrypt.h mycrypt_argchk.h mycrypt_custom.h

#The default rule for make builds the libtomcrypt library.
default:library mycrypt.h mycrypt_cfg.h

#These are the rules to make certain object files.
rsa.o: rsa.c rsa_sys.c
ecc.o: ecc.c ecc_sys.c
dh.o: dh.c dh_sys.c
aes.o: aes.c aes_tab.c
sha512.o: sha512.c sha384.c

#This rule makes the libtomcrypt library.
library: $(OBJECTS) 
	$(AR) $(ARFLAGS) $(LIBNAME) $(OBJECTS)
	ranlib $(LIBNAME)

#This rule makes the test program included with libtomcrypt
test: library $(TESTOBJECTS)
	$(CC) $(TESTOBJECTS) $(LIBNAME) -o $(TEST) $(WARN)

#This rule makes the hash program included with libtomcrypt
hashsum: library $(HASHOBJECTS)
	$(CC) $(HASHOBJECTS) $(LIBNAME) -o $(HASH) $(WARN)

#makes the crypt program
crypt: library $(CRYPTOBJECTS)
	$(CC) $(CRYPTOBJECTS) $(LIBNAME) -o $(CRYPT) $(WARN)

#makes the small program
small: library $(SMALLOBJECTS)
	$(CC) $(SMALLOBJECTS) $(LIBNAME) -o $(SMALL) $(WARN)

#This rule installs the library and the header files. This must be run
#as root in order to have a high enough permission to write to the correct
#directories and to set the owner and group to root.
install: library docs
	install -d -g root -o root $(DESTDIR)$(LIBPATH)
	install -d -g root -o root $(DESTDIR)$(INCPATH)
	install -d -g root -o root $(DESTDIR)$(DATAPATH)
	install -g root -o root $(LIBNAME) $(DESTDIR)$(LIBPATH)
	install -g root -o root $(HEADERS) $(DESTDIR)$(INCPATH)
	install -g root -o root crypt.pdf $(DESTDIR)$(DATAPATH)

#This rule cleans the source tree of all compiled code, not including the pdf
#documentation.
clean:
	rm -f $(OBJECTS) $(TESTOBJECTS) $(HASHOBJECTS) $(CRYPTOBJECTS) $(SMALLOBJECTS) $(LEFTOVERS) $(LIBNAME)
	rm -f $(TEST) $(HASH) $(COMPRESSED)
	rm -f *stackdump *.lib *.exe *.obj demos/*.obj *.bat

#This builds the crypt.pdf file. Note that the rm -f *.pdf has been removed
#from the clean command! This is because most people would like to keep the
#nice pre-compiled crypt.pdf that comes with libtomcrypt! We only need to
#delete it if we are rebuilding it.
docs: crypt.tex
	rm -f crypt.pdf
	rm -f $(LEFTOVERS)
	latex crypt > /dev/null
	makeindex crypt > /dev/null
	pdflatex crypt > /dev/null
	rm -f $(LEFTOVERS)
       
#zipup the project (take that!)
zipup: clean docs
	cd .. ; rm -rf crypt* libtomcrypt-$(VERSION) ; mkdir libtomcrypt-$(VERSION) ; \
	cp -R ./libtomcrypt/* ./libtomcrypt-$(VERSION)/ ; tar -c libtomcrypt-$(VERSION)/* > crypt-$(VERSION).tar ; \
	bzip2 -9vv crypt-$(VERSION).tar ; zip -9 -r crypt-$(VERSION).zip libtomcrypt-$(VERSION)/*
