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
VERSION=0.95

#ch1-01-1
# Compiler and Linker Names
#CC=gcc
#LD=ld

# Archiver [makes .a files]
#AR=ar
#ARFLAGS=r
#ch1-01-1

#ch1-01-3
# Compilation flags. Note the += does not write over the user's CFLAGS!
CFLAGS += -c -I./ -Wall -Wsign-compare -W -Wshadow 
# -Werror

# optimize for SPEED
#CFLAGS += -O3 -funroll-loops

#add -fomit-frame-pointer.  v3.2 is buggy for certain platforms!
#CFLAGS += -fomit-frame-pointer

# optimize for SIZE
CFLAGS += -Os

# compile for DEBUGING
#CFLAGS += -g3
#ch1-01-3

#These flags control how the library gets built.

#Output filenames for various targets.
LIBNAME=libtomcrypt.a
TEST=test
HASH=hashsum
CRYPT=encrypt
SMALL=small
PROF=x86_prof
TV=tv_gen

#LIBPATH-The directory for libtomcrypt to be installed to.
#INCPATH-The directory to install the header files for libtomcrypt.
#DATAPATH-The directory to install the pdf docs.
DESTDIR=
LIBPATH=/usr/lib
INCPATH=/usr/include
DATAPATH=/usr/share/doc/libtomcrypt/pdf

#List of objects to compile.

#Leave MPI built-in or force developer to link against libtommath?
MPIOBJECT=mpi.o

OBJECTS=keyring.o gf.o strings.o base64.o \
\
crypt.o                    crypt_find_cipher.o      crypt_find_hash_any.o      \
crypt_hash_is_valid.o      crypt_register_hash.o    crypt_unregister_prng.o    \
crypt_argchk.o             crypt_find_cipher_any.o  crypt_find_hash_id.o       \
crypt_prng_descriptor.o    crypt_register_prng.o    crypt_cipher_descriptor.o  \
crypt_find_cipher_id.o     crypt_find_prng.o        crypt_prng_is_valid.o      \
crypt_unregister_cipher.o  crypt_cipher_is_valid.o  crypt_find_hash.o          \
crypt_hash_descriptor.o    crypt_register_cipher.o  crypt_unregister_hash.o    \
\
sprng.o yarrow.o rc4.o rng_get_bytes.o  rng_make_prng.o \
\
rand_prime.o is_prime.o \
\
ecc.o  dh.o \
\
rsa.o rsa_exptmod.o  rsa_free.o  rsa_make_key.o \
\
dsa_export.o  dsa_free.o  dsa_import.o  dsa_make_key.o  dsa_sign_hash.o  dsa_verify_hash.o  dsa_verify_key.o \
\
xtea.o aes.o des.o safer_tab.o safer.o saferp.o rc2.o \
rc6.o rc5.o cast5.o noekeon.o blowfish.o twofish.o skipjack.o \
\
md2.o md4.o md5.o sha1.o sha256.o sha512.o tiger.o whirl.o \
rmd128.o rmd160.o \
\
packet_store_header.o  packet_valid_header.o \
\
eax_addheader.o  eax_decrypt.o  eax_decrypt_verify_memory.o  eax_done.o  eax_encrypt.o  \
eax_encrypt_authenticate_memory.o  eax_init.o  eax_test.o \
\
ocb_decrypt.o  ocb_decrypt_verify_memory.o  ocb_done_decrypt.o  ocb_done_encrypt.o  \
ocb_encrypt.o  ocb_encrypt_authenticate_memory.o  ocb_init.o  ocb_ntz.o  \
ocb_shift_xor.o  ocb_test.o s_ocb_done.o \
\
omac_done.o  omac_file.o  omac_init.o  omac_memory.o  omac_process.o  omac_test.o \
\
pmac_done.o  pmac_file.o  pmac_init.o  pmac_memory.o  pmac_ntz.o  pmac_process.o  \
pmac_shift_xor.o  pmac_test.o \
\
cbc_start.o cbc_encrypt.o cbc_decrypt.o \
cfb_start.o cfb_encrypt.o cfb_decrypt.o \
ofb_start.o ofb_encrypt.o ofb_decrypt.o \
ctr_start.o ctr_encrypt.o ctr_decrypt.o \
ecb_start.o ecb_encrypt.o ecb_decrypt.o \
\
hash_file.o  hash_filehandle.o  hash_memory.o \
\
hmac_done.o  hmac_file.o  hmac_init.o  hmac_memory.o  hmac_process.o  hmac_test.o \
\
pkcs_1_mgf1.o pkcs_1_oaep_encode.o pkcs_1_oaep_decode.o  \
pkcs_1_pss_encode.o pkcs_1_pss_decode.o pkcs_1_i2osp.o pkcs_1_os2ip.o \
\
pkcs_5_1.o pkcs_5_2.o \
\
burn_stack.o zeromem.o \
$(MPIOBJECT)

TESTOBJECTS=demos/test.o
HASHOBJECTS=demos/hashsum.o
CRYPTOBJECTS=demos/encrypt.o
SMALLOBJECTS=demos/small.o
PROFS=demos/x86_prof.o
TVS=demos/tv_gen.o

#Files left over from making the crypt.pdf.
LEFTOVERS=*.dvi *.log *.aux *.toc *.idx *.ilg *.ind

#Compressed filenames
COMPRESSED=crypt.tar.bz2 crypt.zip crypt.tar.gz

#Header files used by libtomcrypt.
HEADERS=tommath.h mycrypt_cfg.h mycrypt_gf.h mycrypt_kr.h \
mycrypt_misc.h  mycrypt_prng.h mycrypt_cipher.h  mycrypt_hash.h \
mycrypt_macros.h  mycrypt_pk.h mycrypt.h mycrypt_argchk.h \
mycrypt_custom.h mycrypt_pkcs.h

#The default rule for make builds the libtomcrypt library.
default:library mycrypt.h mycrypt_cfg.h

#These are the rules to make certain object files.
rsa.o: rsa.c rsa_sys.c
ecc.o: ecc.c ecc_sys.c
dh.o: dh.c dh_sys.c
aes.o: aes.c aes_tab.c
twofish.o: twofish.c twofish_tab.c
sha512.o: sha512.c sha384.c
sha256.o: sha256.c sha224.c

#This rule makes the libtomcrypt library.
library: $(LIBNAME)

$(LIBNAME): $(OBJECTS)
	$(AR) $(ARFLAGS) $@ $(OBJECTS) 

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
	
x86_prof: library $(PROFS)
	$(CC) $(PROFS) $(LIBNAME) -o $(PROF)

tv_gen: library $(TVS)
	$(CC) $(TVS) $(LIBNAME) -o $(TV)


#make a profiled library (takes a while!!!)
#
# This will build the library with profile generation
# then run the test demo and rebuild the library.
# 
# So far I've seen improvements in the MP math
#
# This works with GCC v3.3.x [tested with 3.3.3]
profiled: $(TESTOBJECTS)
	make CFLAGS="$(CFLAGS) -fprofile-arcs"
	$(CC) $(TESTOBJECTS) $(LIBNAME) -o $(TEST)
	./test
	rm -f *.a *.o test demos/test.o
	make CFLAGS="$(CFLAGS) -fbranch-probabilities"


#Profiling in GCC 3.4.x is a little diff.  
#
#Tested with GCC v3.4.0
profiled34: $(TESTOBJECTS)
	make CFLAGS="$(CFLAGS) -fprofile-generate"
	$(CC) $(TESTOBJECTS) $(LIBNAME) -lgcov -o $(TEST)
	./test
	rm -f *.a *.o test demos/test.o
	make CFLAGS="$(CFLAGS) -fprofile-use"


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
	rm -f $(TEST) $(HASH) $(COMPRESSED) $(PROFS) $(PROF) $(TVS) $(TV)
	rm -f *.a *.dll *stackdump *.lib *.exe *.obj demos/*.obj demos/*.o *.bat *.txt *.il *.da demos/*.il demos/*.da *.dyn *.dpi \
         *.gcda *.gcno demos/*.gcno demos/*.gcda *~

#This builds the crypt.pdf file. Note that the rm -f *.pdf has been removed
#from the clean command! This is because most people would like to keep the
#nice pre-compiled crypt.pdf that comes with libtomcrypt! We only need to
#delete it if we are rebuilding it.
docs: crypt.tex
	rm -f crypt.pdf $(LEFTOVERS)
	latex crypt > /dev/null
	makeindex crypt > /dev/null
	latex crypt > /dev/null
	latex crypt > /dev/null
	dvipdf crypt
	rm -f $(LEFTOVERS)
       
#beta
beta: clean
	cd .. ; rm -rf crypt* libtomcrypt-$(VERSION)-beta ; mkdir libtomcrypt-$(VERSION)-beta ; \
	cp -R ./libtomcrypt/* ./libtomcrypt-$(VERSION)-beta/ ; tar -c libtomcrypt-$(VERSION)-beta/* > crypt-$(VERSION)-beta.tar ; \
	bzip2 -9vv crypt-$(VERSION)-beta.tar ; zip -9 -r crypt-$(VERSION)-beta.zip libtomcrypt-$(VERSION)-beta/*

#zipup the project (take that!)
zipup: clean docs
	cd .. ; rm -rf crypt* libtomcrypt-$(VERSION) ; mkdir libtomcrypt-$(VERSION) ; \
	cp -R ./libtomcrypt/* ./libtomcrypt-$(VERSION)/ ; tar -c libtomcrypt-$(VERSION)/* > crypt-$(VERSION).tar ; \
	bzip2 -9vv crypt-$(VERSION).tar ; zip -9 -r crypt-$(VERSION).zip libtomcrypt-$(VERSION)/*
