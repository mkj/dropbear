CFLAGS += -I../src/headers -I./ -Wall -W

OBJECTS = base64_test.o cipher_hash_test.o der_tests.o dh_tests.o                        \
dsa_test.o ecc_test.o mac_test.o modes_test.o pkcs_1_test.o rsa_test.o                   \
store_test.o test.o x86_prof.o

default: libtomcrypt_prof.a

libtomcrypt_prof.a: $(OBJECTS)
	$(AR) $(ARFLAGS) libtomcrypt_prof.a $(OBJECTS)
	ranlib libtomcrypt_prof.a

clean:
	rm -f *.o *.a

