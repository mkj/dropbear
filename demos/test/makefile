# make test harness, it is good.
CFLAGS += -Wall -W -Os -I../../ -I./

# add -g3 for ccmalloc debugging 
#CFLAGS += -g3

# if you're not debugging
CFLAGS += -fomit-frame-pointer

default: test

OBJECTS=test.o cipher_hash_test.o mac_test.o modes_test.o \
pkcs_1_test.o store_test.o rsa_test.o ecc_test.o dsa_test.o dh_tests.o der_tests.o 

#uncomment this to get heap checking [e.g. memory leaks].  Note 
#that you *MUST* build libtomcrypt.a with -g3 enabled [and make install it]
#
#
#CCMALLOC = -lccmalloc -ldl

test: $(OBJECTS)
	$(CC) $(OBJECTS) /usr/lib/libtomcrypt.a  $(CCMALLOC) -o test
	
clean:
	rm -rf test *.o *.obj *.exe *~	.libs
