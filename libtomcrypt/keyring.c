/* Provides keyring functionality for libtomcrypt, Tom St Denis */
#include <mycrypt.h>

#ifdef KR

static const unsigned char key_magic[4]  = { 0x12, 0x34, 0x56, 0x78 };
static const unsigned char file_magic[4] = { 0x9A, 0xBC, 0xDE, 0xF0 };
static const unsigned char sign_magic[4] = { 0x87, 0x56, 0x43, 0x21 };
static const unsigned char enc_magic[4]  = { 0x0F, 0xED, 0xCB, 0xA9 };

static const unsigned long crc_table[256] = {
  0x00000000UL, 0x77073096UL, 0xee0e612cUL, 0x990951baUL, 0x076dc419UL,
  0x706af48fUL, 0xe963a535UL, 0x9e6495a3UL, 0x0edb8832UL, 0x79dcb8a4UL,
  0xe0d5e91eUL, 0x97d2d988UL, 0x09b64c2bUL, 0x7eb17cbdUL, 0xe7b82d07UL,
  0x90bf1d91UL, 0x1db71064UL, 0x6ab020f2UL, 0xf3b97148UL, 0x84be41deUL,
  0x1adad47dUL, 0x6ddde4ebUL, 0xf4d4b551UL, 0x83d385c7UL, 0x136c9856UL,
  0x646ba8c0UL, 0xfd62f97aUL, 0x8a65c9ecUL, 0x14015c4fUL, 0x63066cd9UL,
  0xfa0f3d63UL, 0x8d080df5UL, 0x3b6e20c8UL, 0x4c69105eUL, 0xd56041e4UL,
  0xa2677172UL, 0x3c03e4d1UL, 0x4b04d447UL, 0xd20d85fdUL, 0xa50ab56bUL,
  0x35b5a8faUL, 0x42b2986cUL, 0xdbbbc9d6UL, 0xacbcf940UL, 0x32d86ce3UL,
  0x45df5c75UL, 0xdcd60dcfUL, 0xabd13d59UL, 0x26d930acUL, 0x51de003aUL,
  0xc8d75180UL, 0xbfd06116UL, 0x21b4f4b5UL, 0x56b3c423UL, 0xcfba9599UL,
  0xb8bda50fUL, 0x2802b89eUL, 0x5f058808UL, 0xc60cd9b2UL, 0xb10be924UL,
  0x2f6f7c87UL, 0x58684c11UL, 0xc1611dabUL, 0xb6662d3dUL, 0x76dc4190UL,
  0x01db7106UL, 0x98d220bcUL, 0xefd5102aUL, 0x71b18589UL, 0x06b6b51fUL,
  0x9fbfe4a5UL, 0xe8b8d433UL, 0x7807c9a2UL, 0x0f00f934UL, 0x9609a88eUL,
  0xe10e9818UL, 0x7f6a0dbbUL, 0x086d3d2dUL, 0x91646c97UL, 0xe6635c01UL,
  0x6b6b51f4UL, 0x1c6c6162UL, 0x856530d8UL, 0xf262004eUL, 0x6c0695edUL,
  0x1b01a57bUL, 0x8208f4c1UL, 0xf50fc457UL, 0x65b0d9c6UL, 0x12b7e950UL,
  0x8bbeb8eaUL, 0xfcb9887cUL, 0x62dd1ddfUL, 0x15da2d49UL, 0x8cd37cf3UL,
  0xfbd44c65UL, 0x4db26158UL, 0x3ab551ceUL, 0xa3bc0074UL, 0xd4bb30e2UL,
  0x4adfa541UL, 0x3dd895d7UL, 0xa4d1c46dUL, 0xd3d6f4fbUL, 0x4369e96aUL,
  0x346ed9fcUL, 0xad678846UL, 0xda60b8d0UL, 0x44042d73UL, 0x33031de5UL,
  0xaa0a4c5fUL, 0xdd0d7cc9UL, 0x5005713cUL, 0x270241aaUL, 0xbe0b1010UL,
  0xc90c2086UL, 0x5768b525UL, 0x206f85b3UL, 0xb966d409UL, 0xce61e49fUL,
  0x5edef90eUL, 0x29d9c998UL, 0xb0d09822UL, 0xc7d7a8b4UL, 0x59b33d17UL,
  0x2eb40d81UL, 0xb7bd5c3bUL, 0xc0ba6cadUL, 0xedb88320UL, 0x9abfb3b6UL,
  0x03b6e20cUL, 0x74b1d29aUL, 0xead54739UL, 0x9dd277afUL, 0x04db2615UL,
  0x73dc1683UL, 0xe3630b12UL, 0x94643b84UL, 0x0d6d6a3eUL, 0x7a6a5aa8UL,
  0xe40ecf0bUL, 0x9309ff9dUL, 0x0a00ae27UL, 0x7d079eb1UL, 0xf00f9344UL,
  0x8708a3d2UL, 0x1e01f268UL, 0x6906c2feUL, 0xf762575dUL, 0x806567cbUL,
  0x196c3671UL, 0x6e6b06e7UL, 0xfed41b76UL, 0x89d32be0UL, 0x10da7a5aUL,
  0x67dd4accUL, 0xf9b9df6fUL, 0x8ebeeff9UL, 0x17b7be43UL, 0x60b08ed5UL,
  0xd6d6a3e8UL, 0xa1d1937eUL, 0x38d8c2c4UL, 0x4fdff252UL, 0xd1bb67f1UL,
  0xa6bc5767UL, 0x3fb506ddUL, 0x48b2364bUL, 0xd80d2bdaUL, 0xaf0a1b4cUL,
  0x36034af6UL, 0x41047a60UL, 0xdf60efc3UL, 0xa867df55UL, 0x316e8eefUL,
  0x4669be79UL, 0xcb61b38cUL, 0xbc66831aUL, 0x256fd2a0UL, 0x5268e236UL,
  0xcc0c7795UL, 0xbb0b4703UL, 0x220216b9UL, 0x5505262fUL, 0xc5ba3bbeUL,
  0xb2bd0b28UL, 0x2bb45a92UL, 0x5cb36a04UL, 0xc2d7ffa7UL, 0xb5d0cf31UL,
  0x2cd99e8bUL, 0x5bdeae1dUL, 0x9b64c2b0UL, 0xec63f226UL, 0x756aa39cUL,
  0x026d930aUL, 0x9c0906a9UL, 0xeb0e363fUL, 0x72076785UL, 0x05005713UL,
  0x95bf4a82UL, 0xe2b87a14UL, 0x7bb12baeUL, 0x0cb61b38UL, 0x92d28e9bUL,
  0xe5d5be0dUL, 0x7cdcefb7UL, 0x0bdbdf21UL, 0x86d3d2d4UL, 0xf1d4e242UL,
  0x68ddb3f8UL, 0x1fda836eUL, 0x81be16cdUL, 0xf6b9265bUL, 0x6fb077e1UL,
  0x18b74777UL, 0x88085ae6UL, 0xff0f6a70UL, 0x66063bcaUL, 0x11010b5cUL,
  0x8f659effUL, 0xf862ae69UL, 0x616bffd3UL, 0x166ccf45UL, 0xa00ae278UL,
  0xd70dd2eeUL, 0x4e048354UL, 0x3903b3c2UL, 0xa7672661UL, 0xd06016f7UL,
  0x4969474dUL, 0x3e6e77dbUL, 0xaed16a4aUL, 0xd9d65adcUL, 0x40df0b66UL,
  0x37d83bf0UL, 0xa9bcae53UL, 0xdebb9ec5UL, 0x47b2cf7fUL, 0x30b5ffe9UL,
  0xbdbdf21cUL, 0xcabac28aUL, 0x53b39330UL, 0x24b4a3a6UL, 0xbad03605UL,
  0xcdd70693UL, 0x54de5729UL, 0x23d967bfUL, 0xb3667a2eUL, 0xc4614ab8UL,
  0x5d681b02UL, 0x2a6f2b94UL, 0xb40bbe37UL, 0xc30c8ea1UL, 0x5a05df1bUL,
  0x2d02ef8dUL
};

#define DO1(buf) crc = crc_table[(crc ^ (*buf++)) & 0xff] ^ (crc >> 8);
#define DO2(buf)  DO1(buf); DO1(buf);
#define DO4(buf)  DO2(buf); DO2(buf);
#define DO8(buf)  DO4(buf); DO4(buf);

static unsigned long crc32 (unsigned long crc, const unsigned char *buf, unsigned long len)
{
  //_ARGCHK(buf != NULL  && len == 0);
  crc = crc ^ 0xffffffffL;
  while (len >= 8) {
      DO8 (buf);
      len -= 8;
  }
  
  if (len > 0) {
    do {
	   DO1 (buf);
    } while (--len > 0);
  }    
  return crc ^ 0xffffffffUL;
}

int kr_init(pk_key **pk)
{
   _ARGCHK(pk != NULL);

   *pk = XCALLOC(1, sizeof(pk_key));
   if (*pk == NULL) {
      return CRYPT_MEM;
   }
   (*pk)->system = NON_KEY;
   return CRYPT_OK;
}

unsigned long kr_crc(const unsigned char *name, const unsigned char *email, const unsigned char *description)
{
   unsigned long crc;
   _ARGCHK(name != NULL);
   _ARGCHK(email != NULL);
   _ARGCHK(description != NULL);
   crc = crc32(0UL, NULL, 0UL);
   crc = crc32(crc, name,  (unsigned long)MIN(MAXLEN, strlen((char *)name)));
   crc = crc32(crc, email, (unsigned long)MIN(MAXLEN, strlen((char *)email)));
   return crc32(crc, description, (unsigned long)MIN(MAXLEN, strlen((char *)description)));
}

pk_key *kr_find(pk_key *pk, unsigned long ID)
{
   _ARGCHK(pk != NULL);

   while (pk != NULL) {
        if (pk->system != NON_KEY && pk->ID == ID) {
           return pk;
        }
        pk = pk->next;
   }
   return NULL;
}

pk_key *kr_find_name(pk_key *pk, const char *name)
{
   _ARGCHK(pk != NULL);
   _ARGCHK(name != NULL);

   while (pk != NULL) {
        if (pk->system != NON_KEY && strncmp((char *)pk->name, (char *)name, sizeof(pk->name)-1) == 0) {
           return pk;
        }
        pk = pk->next;
   }
   return NULL;
}
 

int kr_add(pk_key *pk, int key_type, int sys, const unsigned char *name, 
           const unsigned char *email, const unsigned char *description, const _pk_key *key)
{
   _ARGCHK(pk != NULL);
   _ARGCHK(name != NULL);
   _ARGCHK(email != NULL);
   _ARGCHK(description != NULL);
   _ARGCHK(key != NULL);

   /* check parameters */
   if (key_type != PK_PRIVATE && key_type != PK_PRIVATE_OPTIMIZED && key_type != PK_PUBLIC) {
      return CRYPT_PK_INVALID_TYPE;
   }
 
   if (sys != RSA_KEY && sys != DH_KEY && sys != ECC_KEY) {
      return CRYPT_PK_INVALID_SYSTEM;
   }

   /* see if its a dupe  */
   if (kr_find(pk, kr_crc(name, email, description)) != NULL) {
      return CRYPT_PK_DUP;
   }
   
   /* find spot in key ring */
   while (pk->system != NON_KEY) {
         if (pk->next == NULL) {
            return CRYPT_ERROR;
         }
         pk = pk->next;
   }

   /* now we have a spot make a next spot */
   pk->next = XCALLOC(1, sizeof(pk_key));
   if (pk->next == NULL) {
      return CRYPT_MEM;
   }
   pk->next->system = NON_KEY;

   /* now add this new data to this ring spot */
   pk->key_type = key_type;
   pk->system   = sys;
   strncpy((char *)pk->name, (char *)name, sizeof(pk->name)-1);
   strncpy((char *)pk->email, (char *)email, sizeof(pk->email)-1);
   strncpy((char *)pk->description, (char *)description, sizeof(pk->description)-1);
   pk->ID       = kr_crc(pk->name, pk->email, pk->description);

   /* clear the memory area */
   zeromem(&(pk->key), sizeof(pk->key));

   /* copy the key */
   switch (sys) {
         case RSA_KEY:
              memcpy(&(pk->key.rsa), &(key->rsa), sizeof(key->rsa));
              break;
         case DH_KEY:
              memcpy(&(pk->key.dh), &(key->dh), sizeof(key->dh));
              break;
         case ECC_KEY:
              memcpy(&(pk->key.ecc), &(key->ecc), sizeof(key->ecc));
              break;
   }
   return CRYPT_OK;
}

int kr_del(pk_key **_pk, unsigned long ID)
{
   pk_key *ppk, *pk;

   _ARGCHK(_pk != NULL);

   pk  = *_pk;
   ppk = NULL;
   while (pk->system != NON_KEY && pk->ID != ID) {
        ppk = pk;
        pk  = pk->next;
        if (pk == NULL) {
           return CRYPT_PK_NOT_FOUND;
        }
   }

   switch (pk->system) {
        case RSA_KEY:
            rsa_free(&(pk->key.rsa));
            break;
        case DH_KEY:
            dh_free(&(pk->key.dh));
            break;
        case ECC_KEY:
            ecc_free(&(pk->key.ecc));
            break;
   }

   if (ppk == NULL) {       /* the first element matches the ID */
      ppk = pk->next;       /* get the 2nd element */
      XFREE(pk);             /* free the first */
      *_pk = ppk;           /* make the first element the second */
   } else {                 /* (not) first element matches the ID */
      ppk->next = pk->next; /* make the previous'es next point to the current next */
      XFREE(pk);             /* free the element */
   }
   return CRYPT_OK;
}

int kr_clear(pk_key **pk)
{
   int err;
   _ARGCHK(pk != NULL);

   while ((*pk)->system != NON_KEY) {
       if ((err = kr_del(pk, (*pk)->ID)) != CRYPT_OK) { 
          return err;
       }
   }       
   XFREE(*pk);
   *pk = NULL;
   return CRYPT_OK;
}

static unsigned long _write(unsigned char *buf, unsigned long len, FILE *f, symmetric_CTR *ctr)
{
#ifdef NO_FILE
   return 0;
#else
   _ARGCHK(buf != NULL);
   _ARGCHK(f   != NULL);
   if (ctr != NULL) {
      if (ctr_encrypt(buf, buf, len, ctr) != CRYPT_OK) {
         return 0;
      }
   }
   return (unsigned long)fwrite(buf, 1, (size_t)len, f);
#endif
}

static unsigned long _read(unsigned char *buf, unsigned long len, FILE *f, symmetric_CTR *ctr)
{
#ifdef NO_FILE
    return 0;
#else
   unsigned long y;
   _ARGCHK(buf != NULL);
   _ARGCHK(f   != NULL);
   y = (unsigned long)fread(buf, 1, (size_t)len, f);
   if (ctr != NULL) {
      if (ctr_decrypt(buf, buf, y, ctr) != CRYPT_OK) {
         return 0;
      }
   }
   return y;
#endif
}

int kr_export(pk_key *pk, unsigned long ID, int key_type, unsigned char *out, unsigned long *outlen)
{
   unsigned char buf[8192], *obuf;
   pk_key *ppk;
   unsigned long len;
   int err;

   _ARGCHK(pk != NULL);
   _ARGCHK(out != NULL);
   _ARGCHK(outlen != NULL);

   /* find the desired key */
   ppk = kr_find(pk, ID);
   if (ppk == NULL) {
      return CRYPT_PK_NOT_FOUND;
   }

   if (ppk->key_type == PK_PUBLIC && key_type != PK_PUBLIC) {
      return CRYPT_PK_NOT_PRIVATE;
   }

   /* this makes PK_PRIVATE an alias for PK_PRIVATE_OPTIMIZED type */
   if (ppk->key_type == PK_PRIVATE_OPTIMIZED && key_type == PK_PRIVATE) {
      key_type = PK_PRIVATE_OPTIMIZED;
   }

   /* now copy the header and various other details */
   memcpy(buf, key_magic, 4);                              /* magic info */
   buf[4] = key_type;                                      /* key type */
   buf[5] = ppk->system;                                   /* system */
   STORE32L(ppk->ID, buf+6);                               /* key ID */
   memcpy(buf+10, ppk->name, MAXLEN);                      /* the name */
   memcpy(buf+10+MAXLEN, ppk->email, MAXLEN);              /* the email */
   memcpy(buf+10+MAXLEN+MAXLEN, ppk->description, MAXLEN); /* the description */
   
   /* export key */
   len = sizeof(buf) - (6 + 4 + MAXLEN*3);
   obuf = buf+6+4+MAXLEN*3;
   switch (ppk->system) {
       case RSA_KEY:
           if ((err = rsa_export(obuf, &len, key_type, &(ppk->key.rsa))) != CRYPT_OK) {
              return err;
           }
           break;
       case DH_KEY:
           if ((err = dh_export(obuf, &len, key_type, &(ppk->key.dh))) != CRYPT_OK) {
              return err;
           }
           break;
       case ECC_KEY:
           if ((err = ecc_export(obuf, &len, key_type, &(ppk->key.ecc))) != CRYPT_OK) {
              return err;
           }
           break;
   }

   /* get the entire length of the packet */
   len += 6 + 4 + 3*MAXLEN;

   if (*outlen < len) {
      #ifdef CLEAN_STACK
          zeromem(buf, sizeof(buf));
      #endif
      return CRYPT_BUFFER_OVERFLOW;
   } else {
      *outlen = len;
      memcpy(out, buf, len);
      #ifdef CLEAN_STACK
          zeromem(buf, sizeof(buf));
      #endif
      return CRYPT_OK;
   }
}

int kr_import(pk_key *pk, const unsigned char *in, unsigned long inlen)
{
   _pk_key key;
   int sys, key_type, err;
   unsigned long ID;

   _ARGCHK(pk != NULL);
   _ARGCHK(in != NULL);

   if (inlen < 10) {
      return CRYPT_INVALID_PACKET;
   }

   if (memcmp(in, key_magic, 4) != 0) {
      return CRYPT_INVALID_PACKET;
   }
   key_type = in[4];                                 /* get type */
   sys      = in[5];                                 /* get system */
   LOAD32L(ID,in+6);                                 /* the ID */

   if (ID != kr_crc(in+10, in+10+MAXLEN, in+10+MAXLEN+MAXLEN)) {
      return CRYPT_INVALID_PACKET;
   }

   zeromem(&key, sizeof(key));
   
   /* size of remaining packet */
   inlen -= 10 + 3*MAXLEN;
   
   switch (sys) {
        case RSA_KEY:
            if ((err = rsa_import(in+10+3*MAXLEN, inlen, &(key.rsa))) != CRYPT_OK) {
               return err;
            }
            break;
        case DH_KEY:
            if ((err = dh_import(in+10+3*MAXLEN, inlen, &(key.dh))) != CRYPT_OK) {
               return err;
            }
            break;
        case ECC_KEY:
            if ((err = ecc_import(in+10+3*MAXLEN, inlen, &(key.ecc))) != CRYPT_OK) {
               return err;
            }
            break;
   }
   return kr_add(pk, key_type, sys, 
                 in+10,                           /* the name */
                 in+10+MAXLEN,                    /* email address */
                 in+10+MAXLEN+MAXLEN,             /* description */
                 &key);
}


int kr_load(pk_key **pk, FILE *in, symmetric_CTR *ctr)
{
   unsigned char buf[8192], blen[4];
   unsigned long len;
   int res, err;

   _ARGCHK(pk != NULL);
   _ARGCHK(in != NULL);

   /* init keyring */
   if ((err = kr_init(pk)) != CRYPT_OK) { 
      return err; 
   }

   /* read in magic bytes */
   if (_read(buf, 6, in, ctr) != 6)           { goto done2; }

   if (memcmp(buf, file_magic, 4) != 0) {
      return CRYPT_INVALID_PACKET;
   }

   len = (unsigned long)buf[4] | ((unsigned long)buf[5] << 8);
   if (len > CRYPT) {
      return CRYPT_INVALID_PACKET;
   }

   /* while there are lengths to read... */
   while (_read(blen, 4, in, ctr) == 4) {
      /* get length */
      LOAD32L(len, blen);

      if (len > (unsigned long)sizeof(buf)) {
         return CRYPT_INVALID_PACKET;
      }

      if (_read(buf, len, in, ctr) != len)           { goto done2; }
      if ((err = kr_import(*pk, buf, len)) != CRYPT_OK) { 
         return err; 
      }
   }

   res = CRYPT_OK;
   goto done;
done2:
   res = CRYPT_ERROR;
done:
#ifdef CLEAN_STACK
   zeromem(buf, sizeof(buf));
#endif
   return res;
}

int kr_save(pk_key *pk, FILE *out, symmetric_CTR *ctr)
{
   unsigned char buf[8192], blen[4];
   unsigned long len;
   int res, err;

   _ARGCHK(pk != NULL);
   _ARGCHK(out != NULL);

   /* write out magic bytes */
   memcpy(buf, file_magic, 4);
   buf[4] = (unsigned char)(CRYPT&255);
   buf[5] = (unsigned char)((CRYPT>>8)&255);
   if (_write(buf, 6, out, ctr) != 6)           { goto done2; }

   while (pk->system != NON_KEY) {
         len = sizeof(buf);
         if ((err = kr_export(pk, pk->ID, pk->key_type, buf, &len)) != CRYPT_OK) { 
            return err;
         }
          
         STORE32L(len, blen);
         if (_write(blen, 4, out, ctr) != 4)    { goto done2; }
         if (_write(buf, len, out, ctr) != len) { goto done2; }

         pk = pk->next;
   }
         
   res = CRYPT_OK;
   goto done;
done2:
   res = CRYPT_ERROR;
done:
#ifdef CLEAN_STACK
   zeromem(buf, sizeof(buf));
#endif
   return res;
}

int kr_make_key(pk_key *pk, prng_state *prng, int wprng, 
                int sys, int keysize, const unsigned char *name,
                const unsigned char *email, const unsigned char *description)
{
   _pk_key key;
   int key_type, err;

   _ARGCHK(pk != NULL);
   _ARGCHK(name != NULL);
   _ARGCHK(email != NULL);
   _ARGCHK(description != NULL);

   /* valid PRNG? */
   if ((err = prng_is_valid(wprng)) != CRYPT_OK) {
      return err;
   }

   /* make the key first */
   zeromem(&key, sizeof(key));
   switch (sys) {
      case RSA_KEY: 
          if ((err = rsa_make_key(prng, wprng, keysize, 65537, &(key.rsa))) != CRYPT_OK) {
             return err;
          }
          key_type = key.rsa.type;
          break;
      case DH_KEY: 
          if ((err = dh_make_key(prng, wprng, keysize, &(key.dh))) != CRYPT_OK) {
             return err;
          }
          key_type = key.dh.type;
          break;
      case ECC_KEY: 
          if ((err = ecc_make_key(prng, wprng, keysize, &(key.ecc))) != CRYPT_OK) {
             return err;
          }
          key_type = key.ecc.type;
          break;
      default:
          return CRYPT_PK_INVALID_SYSTEM;
   }

   /* now add the key */
   if ((err = kr_add(pk, key_type, sys, name, email, description, &key)) != CRYPT_OK) {
      return err;
   }

#ifdef CLEAN_STACK
   zeromem(&key, sizeof(key));
#endif
   return CRYPT_OK;
}

int kr_encrypt_key(pk_key *pk, unsigned long ID, 
                   const unsigned char *in, unsigned long inlen,
                   unsigned char *out, unsigned long *outlen,
                   prng_state *prng, int wprng, int hash)
{
   unsigned char buf[8192];
   unsigned long len;
   pk_key *kr;
   int err;

   _ARGCHK(pk != NULL);
   _ARGCHK(in != NULL);
   _ARGCHK(out != NULL);
   _ARGCHK(outlen != NULL);

   /* find the key */
   kr = kr_find(pk, ID);
   if (kr == NULL) {
      return CRYPT_PK_NOT_FOUND;
   }

   /* store the header */
   memcpy(buf, enc_magic, 4);

   /* now store the ID */
   STORE32L(kr->ID,buf+4);

   /* now encrypt it */
   len = sizeof(buf)-12;
   switch (kr->system) {
        case RSA_KEY:
            if ((err = rsa_encrypt_key(in, inlen, buf+12, &len, prng, wprng, &(kr->key.rsa))) != CRYPT_OK) {
               return err;
            }
            break;
        case DH_KEY:
            if ((err = dh_encrypt_key(in, inlen, buf+12, &len, prng, wprng, hash, &(kr->key.dh))) != CRYPT_OK) {
               return err;
            }
            break;
        case ECC_KEY:
            if ((err = ecc_encrypt_key(in, inlen, buf+12, &len, prng, wprng, hash, &(kr->key.ecc))) != CRYPT_OK) {
               return err;
            }
            break;
    }
    STORE32L(len,buf+8);
    len += 12;

    if (len > *outlen) {
       #ifdef CLEAN_STACK
           zeromem(buf, sizeof(buf));
       #endif
       return CRYPT_BUFFER_OVERFLOW;
    } else {
       memcpy(out, buf, len);
       #ifdef CLEAN_STACK
           zeromem(buf, sizeof(buf));
       #endif
       *outlen = len;
       return CRYPT_OK;
    }
}

int kr_decrypt_key(pk_key *pk, const unsigned char *in,
                   unsigned char *out, unsigned long *outlen)
{
   unsigned char buf[8192];
   unsigned long pklen, len, ID;
   pk_key *kr;
   int err;

   _ARGCHK(pk != NULL);
   _ARGCHK(in != NULL);
   _ARGCHK(out != NULL);
   _ARGCHK(outlen != NULL);

   /* check magic header */
   if (memcmp(in, enc_magic, 4)) {
      return CRYPT_INVALID_PACKET;
   }

   /* now try to find key */
   LOAD32L(ID,in+4);
   kr = kr_find(pk, ID);
   if (kr == NULL) {
      return CRYPT_PK_NOT_FOUND;
   }

   /* is it public? */
   if (kr->key_type == PK_PUBLIC) {
      return CRYPT_PK_NOT_PRIVATE;
   }

   /* now try and decrypt it */
   LOAD32L(pklen,in+8);
   len = sizeof(buf);
   switch (kr->system) {
       case RSA_KEY:
           if ((err = rsa_decrypt_key(in+12, pklen, buf, &len, &(kr->key.rsa))) != CRYPT_OK) {
              return err;
           }
           break;
       case DH_KEY:
           if ((err = dh_decrypt_key(in+12, pklen, buf, &len, &(kr->key.dh))) != CRYPT_OK) {
              return err;
           }
           break;
       case ECC_KEY:
           if ((err = ecc_decrypt_key(in+12, pklen, buf, &len, &(kr->key.ecc))) != CRYPT_OK) {
              return err;
           }
           break;
   }

    if (len > *outlen) {
       #ifdef CLEAN_STACK
           zeromem(buf, sizeof(buf));
       #endif
       return CRYPT_BUFFER_OVERFLOW;
    } else {
       memcpy(out, buf, len);
       #ifdef CLEAN_STACK
           zeromem(buf, sizeof(buf));
       #endif
       *outlen = len;
       return CRYPT_OK;
    }
}

int kr_sign_hash(pk_key *pk, unsigned long ID, 
                 const unsigned char *in, unsigned long inlen,
                 unsigned char *out, unsigned long *outlen,
                 prng_state *prng, int wprng)
{
   unsigned char buf[8192];
   unsigned long len;
   pk_key *kr;
   int err;

   _ARGCHK(pk != NULL);
   _ARGCHK(in != NULL);
   _ARGCHK(out != NULL);
   _ARGCHK(outlen != NULL);

   /* find the key */
   kr = kr_find(pk, ID);
   if (kr == NULL) {
      return CRYPT_PK_NOT_FOUND;
   }

   /* is it public? */
   if (kr->key_type == PK_PUBLIC) {
      return CRYPT_PK_NOT_PRIVATE;
   }

   /* store the header */
   memcpy(buf, sign_magic, 4);

   /* now store the ID */
   STORE32L(kr->ID,buf+4);

   /* now sign it */
   len = sizeof(buf)-16;
   switch (kr->system) {
        case RSA_KEY:
            if ((err = rsa_sign_hash(in, inlen, buf+16, &len, &(kr->key.rsa))) != CRYPT_OK) {
               return err;
            }
            break;
        case DH_KEY:
            if ((err = dh_sign_hash(in, inlen, buf+16, &len, prng, wprng, &(kr->key.dh))) != CRYPT_OK) {
               return err;
            }
            break;
        case ECC_KEY:
            if ((err = ecc_sign_hash(in, inlen, buf+16, &len, prng, wprng, &(kr->key.ecc))) != CRYPT_OK) {
               return err;
            }
            break;
    }
    STORE32L(inlen,buf+8);
    STORE32L(len,buf+12);
    len += 16;

    if (len > *outlen) {
       #ifdef CLEAN_STACK
           zeromem(buf, sizeof(buf));
       #endif
       return CRYPT_BUFFER_OVERFLOW;
    } else {
       memcpy(out, buf, len);
       #ifdef CLEAN_STACK
           zeromem(buf, sizeof(buf));
       #endif
       *outlen = len;
       return CRYPT_OK;
    }
}

int kr_verify_hash(pk_key *pk, const unsigned char *in, const unsigned char *hash, 
                   unsigned long hashlen, int *stat)
{
   unsigned long inlen, pklen, ID;
   pk_key *kr;
   int err;

   _ARGCHK(pk != NULL);
   _ARGCHK(in != NULL);
   _ARGCHK(hash != NULL);
   _ARGCHK(stat != NULL);

   /* default to not match */
   *stat = 0;

   /* check magic header */
   if (memcmp(in, sign_magic, 4)) {
      return CRYPT_INVALID_PACKET;
   }

   /* now try to find key */
   LOAD32L(ID,in+4);
   kr = kr_find(pk, ID);
   if (kr == NULL) {
      return CRYPT_PK_NOT_FOUND;
   }

   /* now try and verify it */
   LOAD32L(inlen,in+8);         /* this is the length of the original inlen */
   LOAD32L(pklen,in+12);        /* size of the PK packet */
   if (inlen != hashlen) {      /* size doesn't match means the signature is invalid */
      return CRYPT_OK;
   }

   switch (kr->system) {
       case RSA_KEY:
           if ((err = rsa_verify_hash(in+16, pklen, hash, stat, &(kr->key.rsa))) != CRYPT_OK) {
              return err;
           }
           break;
       case DH_KEY:
           if ((err = dh_verify_hash(in+16, pklen, hash, inlen, stat, &(kr->key.dh))) != CRYPT_OK) {
              return err;
           }
           break;
       case ECC_KEY:
           if ((err = ecc_verify_hash(in+16, pklen, hash, inlen, stat, &(kr->key.ecc))) != CRYPT_OK) {
              return err;
           }
           break;
   }
   return CRYPT_OK;
}

int kr_fingerprint(pk_key *pk, unsigned long ID, int hash,
                   unsigned char *out, unsigned long *outlen)
{
   unsigned char buf[8192];
   unsigned long len;
   int err;

   _ARGCHK(pk != NULL);
   _ARGCHK(out != NULL);
   _ARGCHK(outlen != NULL);

   /* valid hash? */
   if ((err = hash_is_valid(hash)) != CRYPT_OK) {
      return err;
   }

   len = (unsigned long)sizeof(buf);
   if ((err = kr_export(pk, ID, PK_PUBLIC, buf, &len)) != CRYPT_OK) {
      return err;
   }
   
   /* now hash it */
   if ((err = hash_memory(hash, buf, len, out, outlen)) != CRYPT_OK) {
      return err;
   }

#ifdef CLEAN_STACK
   zeromem(buf, sizeof(buf));
#endif
   return CRYPT_OK;
}

#endif


