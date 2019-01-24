/*
 * Dropbear - a SSH2 server
 *
 * Copyright (c) 2002,2003 Matt Johnston
 * All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE. */

#include "includes.h"
#include "dbutil.h"
#include "ed25519.h"
#include "buffer.h"
#include "ssh.h"

/* Handle ed25519 (Edwards 25519 elliptic curve)
 * operations, such as key reading, signing, verification. Key generation
 * will be in gened25519.c, since it isn't required in the server itself.
 */

#ifdef DROPBEAR_ED25519

/* --- Based on tweetnacl.c v20140427.
 *
 * TODO(pts): Is tinyssh's implementation faster?
 * TODO(pts): Reuse a faster sha512 hash in libtomcrypt?
 *            Is it faster? Does it add extra code?
 *            It can be use do reduce copying in buf_ed25519_verify and
 *            buf_ed25519_sign, in a multi-step call to sha512.
 */

#define FOR(i,n) for (i = 0;i < n;++i)

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int64_t i64;
typedef i64 gf[16];

static const u8 _0[16], _9[32] = {9};
static const gf
  gf0,
  gf1 = {1},
  _121665 = {0xDB41,1},
  D = {0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203},
  D2 = {0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406},
  X = {0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169},
  Y = {0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666},
  I = {0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83};

static u64 dl64(const u8 *x) {
  u64 u=0;
  u32 i;
  FOR(i,8) u=(u<<8)|x[i];
  return u;
}

static void ts64(u8 *x,u64 u) {
  int i;
  for (i = 7;i >= 0;--i) { x[i] = u; u >>= 8; }
}

static int vn(const u8 *x,const u8 *y,unsigned n) {
  u32 i,d = 0;
  FOR(i,n) d |= x[i]^y[i];
  return (1 & ((d - 1) >> 8)) - 1;
}

static int crypto_verify_32(const u8 *x,const u8 *y) {
  return vn(x,y,32);
}

static void set25519(gf r, const gf a) {
  int i;
  FOR(i,16) r[i]=a[i];
}

static void car25519(gf o) {
  int i;
  i64 c;
  FOR(i,16) {
    o[i]+=(1LL<<16);
    c=o[i]>>16;
    o[(i+1)*(i<15)]+=c-1+37*(c-1)*(i==15);
    o[i]-=c<<16;
  }
}

static void sel25519(gf p,gf q,int b) {
  i64 t,i,c=~(b-1);
  FOR(i,16) {
    t= c&(p[i]^q[i]);
    p[i]^=t;
    q[i]^=t;
  }
}

static void pack25519(u8 *o,const gf n) {
  int i,j,b;
  gf m,t;
  FOR(i,16) t[i]=n[i];
  car25519(t);
  car25519(t);
  car25519(t);
  FOR(j,2) {
    m[0]=t[0]-0xffed;
    for(i=1;i<15;i++) {
      m[i]=t[i]-0xffff-((m[i-1]>>16)&1);
      m[i-1]&=0xffff;
    }
    m[15]=t[15]-0x7fff-((m[14]>>16)&1);
    b=(m[15]>>16)&1;
    m[14]&=0xffff;
    sel25519(t,m,1-b);
  }
  FOR(i,16) {
    o[2*i]=t[i]&0xff;
    o[2*i+1]=t[i]>>8;
  }
}

static int neq25519(const gf a, const gf b) {
  u8 c[32],d[32];
  pack25519(c,a);
  pack25519(d,b);
  return crypto_verify_32(c,d);
}

static u8 par25519(const gf a) {
  u8 d[32];
  pack25519(d,a);
  return d[0]&1;
}

static void unpack25519(gf o, const u8 *n) {
  int i;
  FOR(i,16) o[i]=n[2*i]+((i64)n[2*i+1]<<8);
  o[15]&=0x7fff;
}

static void A(gf o,const gf a,const gf b) {
  int i;
  FOR(i,16) o[i]=a[i]+b[i];
}

static void Z(gf o,const gf a,const gf b) {
  int i;
  FOR(i,16) o[i]=a[i]-b[i];
}

static void M(gf o,const gf a,const gf b) {
  i64 i,j,t[31];
  FOR(i,31) t[i]=0;
  FOR(i,16) FOR(j,16) t[i+j]+=a[i]*b[j];
  FOR(i,15) t[i]+=38*t[i+16];
  FOR(i,16) o[i]=t[i];
  car25519(o);
  car25519(o);
}

static void S(gf o,const gf a) {
  M(o,a,a);
}

static void inv25519(gf o,const gf i) {
  gf c;
  int a;
  FOR(a,16) c[a]=i[a];
  for(a=253;a>=0;a--) {
    S(c,c);
    if(a!=2&&a!=4) M(c,c,i);
  }
  FOR(a,16) o[a]=c[a];
}

static void pow2523(gf o,const gf i) {
  gf c;
  int a;
  FOR(a,16) c[a]=i[a];
  for(a=250;a>=0;a--) {
    S(c,c);
    if(a!=1) M(c,c,i);
  }
  FOR(a,16) o[a]=c[a];
}

static u64 R(u64 x,int c) { return (x >> c) | (x << (64 - c)); }
static u64 Ch(u64 x,u64 y,u64 z) { return (x & y) ^ (~x & z); }
static u64 Maj(u64 x,u64 y,u64 z) { return (x & y) ^ (x & z) ^ (y & z); }
static u64 Sigma0(u64 x) { return R(x,28) ^ R(x,34) ^ R(x,39); }
static u64 Sigma1(u64 x) { return R(x,14) ^ R(x,18) ^ R(x,41); }
static u64 sigma0(u64 x) { return R(x, 1) ^ R(x, 8) ^ (x >> 7); }
static u64 sigma1(u64 x) { return R(x,19) ^ R(x,61) ^ (x >> 6); }

static const u64 K[80] = {
  0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
  0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
  0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
  0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
  0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
  0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
  0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
  0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
  0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
  0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
  0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
  0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
  0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
  0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
  0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
  0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
  0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
  0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
  0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
  0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

static int crypto_hashblocks(u8 *x,const u8 *m,u32 n) {
  u64 z[8],b[8],a[8],w[16],t;
  int i,j;
  FOR(i,8) z[i] = a[i] = dl64(x + 8 * i);
  while (n >= 128) {
    FOR(i,16) w[i] = dl64(m + 8 * i);
    FOR(i,80) {
      FOR(j,8) b[j] = a[j];
      t = a[7] + Sigma1(a[4]) + Ch(a[4],a[5],a[6]) + K[i] + w[i%16];
      b[7] = t + Sigma0(a[0]) + Maj(a[0],a[1],a[2]);
      b[3] += t;
      FOR(j,8) a[(j+1)%8] = b[j];
      if (i%16 == 15)
	FOR(j,16)
	  w[j] += w[(j+9)%16] + sigma0(w[(j+1)%16]) + sigma1(w[(j+14)%16]);
    }
    FOR(i,8) { a[i] += z[i]; z[i] = a[i]; }
    m += 128;
    n -= 128;
  }
  FOR(i,8) ts64(x+8*i,z[i]);
  return n;
}

static const u8 iv[64] = {
  0x6a,0x09,0xe6,0x67,0xf3,0xbc,0xc9,0x08,
  0xbb,0x67,0xae,0x85,0x84,0xca,0xa7,0x3b,
  0x3c,0x6e,0xf3,0x72,0xfe,0x94,0xf8,0x2b,
  0xa5,0x4f,0xf5,0x3a,0x5f,0x1d,0x36,0xf1,
  0x51,0x0e,0x52,0x7f,0xad,0xe6,0x82,0xd1,
  0x9b,0x05,0x68,0x8c,0x2b,0x3e,0x6c,0x1f,
  0x1f,0x83,0xd9,0xab,0xfb,0x41,0xbd,0x6b,
  0x5b,0xe0,0xcd,0x19,0x13,0x7e,0x21,0x79
} ;

static int crypto_hash(u8 *out,const u8 *m,u32 n) {
  u8 h[64],x[256];
  u32 i,b = n;
  FOR(i,64) h[i] = iv[i];
  crypto_hashblocks(h,m,n);
  m += n;
  n &= 127;
  m -= n;
  FOR(i,256) x[i] = 0;
  FOR(i,n) x[i] = m[i];
  x[n] = 128;
  n = 256-128*(n<112);
  x[n-9] = 0;
  ts64(x+n-8,b<<3);
  crypto_hashblocks(h,x,n);
  FOR(i,64) out[i] = h[i];
  return 0;
}

static void add(gf p[4],gf q[4]) {
  gf a,b,c,d,t,e,f,g,h;

  Z(a, p[1], p[0]);
  Z(t, q[1], q[0]);
  M(a, a, t);
  A(b, p[0], p[1]);
  A(t, q[0], q[1]);
  M(b, b, t);
  M(c, p[3], q[3]);
  M(c, c, D2);
  M(d, p[2], q[2]);
  A(d, d, d);
  Z(e, b, a);
  Z(f, d, c);
  A(g, d, c);
  A(h, b, a);
  M(p[0], e, f);
  M(p[1], h, g);
  M(p[2], g, f);
  M(p[3], e, h);
}

static void cswap(gf p[4],gf q[4],u8 b) {
  int i;
  FOR(i,4)
    sel25519(p[i],q[i],b);
}

static void pack(u8 *r,gf p[4]) {
  gf tx, ty, zi;
  inv25519(zi, p[2]);
  M(tx, p[0], zi);
  M(ty, p[1], zi);
  pack25519(r, ty);
  r[31] ^= par25519(tx) << 7;
}

static void scalarmult(gf p[4],gf q[4],const u8 *s) {
  int i;
  set25519(p[0],gf0);
  set25519(p[1],gf1);
  set25519(p[2],gf1);
  set25519(p[3],gf0);
  for (i = 255;i >= 0;--i) {
    u8 b = (s[i/8]>>(i&7))&1;
    cswap(p,q,b);
    add(q,p);
    add(p,p);
    cswap(p,q,b);
  }
}

static void scalarbase(gf p[4],const u8 *s) {
  gf q[4];
  set25519(q[0],X);
  set25519(q[1],Y);
  set25519(q[2],gf1);
  M(q[3],X,Y);
  scalarmult(p,q,s);
}

static const u64 L[32] = {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10};

static void modL(u8 *r,i64 x[64]) {
  i64 carry,i,j;
  for (i = 63;i >= 32;--i) {
    carry = 0;
    for (j = i - 32;j < i - 12;++j) {
      x[j] += carry - 16 * x[i] * L[j - (i - 32)];
      carry = (x[j] + 128) >> 8;
      x[j] -= carry << 8;
    }
    x[j] += carry;
    x[i] = 0;
  }
  carry = 0;
  FOR(j,32) {
    x[j] += carry - (x[31] >> 4) * L[j];
    carry = x[j] >> 8;
    x[j] &= 255;
  }
  FOR(j,32) x[j] -= carry * L[j];
  FOR(i,32) {
    x[i+1] += x[i] >> 8;
    r[i] = x[i] & 255;
  }
}

static void reduce(u8 *r) {
  i64 x[64],i;
  FOR(i,64) x[i] = (u64) r[i];
  FOR(i,64) r[i] = 0;
  modL(r,x);
}

/* Modified API: removed smlen. */
static int crypto_sign_m(u8 *sm,const u8 *m,u32 n,const u8 *sk) {
  u8 d[64],h[64],r[64];
  u32 i,j;
  i64 x[64];
  gf p[4];
  crypto_hash(d, sk, 32);
  d[0] &= 248;
  d[31] &= 127;
  d[31] |= 64;
  FOR(i,n) sm[64 + i] = m[i];
  FOR(i,32) sm[32 + i] = d[32 + i];
  crypto_hash(r, sm+32, n+32);
  reduce(r);
  scalarbase(p,r);
  pack(sm,p);
  FOR(i,32) sm[i+32] = sk[i+32];
  crypto_hash(h,sm,n + 64);
  reduce(h);
  FOR(i,64) x[i] = 0;
  FOR(i,32) x[i] = (u64) r[i];
  FOR(i,32) FOR(j,32) x[i+j] += h[i] * (u64) d[j];
  modL(sm + 32,x);
  return 0;
}

static int unpackneg(gf r[4],const u8 p[32]) {
  gf t, chk, num, den, den2, den4, den6;
  set25519(r[2],gf1);
  unpack25519(r[1],p);
  S(num,r[1]);
  M(den,num,D);
  Z(num,num,r[2]);
  A(den,r[2],den);
  S(den2,den);
  S(den4,den2);
  M(den6,den4,den2);
  M(t,den6,num);
  M(t,t,den);
  pow2523(t,t);
  M(t,t,num);
  M(t,t,den);
  M(t,t,den);
  M(r[0],t,den);
  S(chk,r[0]);
  M(chk,chk,den);
  if (neq25519(chk, num)) M(r[0],r[0],I);
  S(chk,r[0]);
  M(chk,chk,den);
  if (neq25519(chk, num)) return -1;
  if (par25519(r[0]) == (p[31]>>7)) Z(r[0],gf0,r[0]);
  M(r[3],r[0],r[1]);
  return 0;
}

/* Modified API: removed m and mlen.
 * Overwrites sm as a side effect.
 */
static int crypto_sign_open_m(u8 *sm,u32 n,const u8 *pk) {
  u32 i;
  u8 t[32],h[64];
  gf p[4],q[4];
  u8 s[32];
  if (n < 64) return -1;
  if (unpackneg(q,pk)) return -1;
  FOR(i,32) s[i] = sm[i+32];
  FOR(i,32) sm[i+32] = pk[i];
  crypto_hash(h,sm,n);
  reduce(h);
  scalarmult(p,q,h);
  scalarbase(q,s);
  add(p,q);
  pack(t,p);
  n -= 64;
  return crypto_verify_32(sm, t);
}

/* --- */

/* Load a ed25519 key from a buffer, initialising the values.
 * The key will have the same format as buf_put_ed25519_key.
 * These should be freed with ed25519_key_free.
 * Returns DROPBEAR_SUCCESS or DROPBEAR_FAILURE */
int buf_get_ed25519_pub_key(buffer* buf, dropbear_ed25519_key *key) {
	/* Format (same as the base64-encoded 2nd word in each line of
	 * ~/.ssh/authorized_keys used by dropbear and OpenSSH):
	 *
	 * "\0\0\0\x0bssh-ed25519\0\0\0 " + pk,
	 * where pk is 32 bytes of public key.
	 * It's 51 bytes in total.
	 */
	if (buf->pos + 51 > buf->len ||
	    0 != memcmp(buf->data + buf->pos, "\0\0\0\x0bssh-ed25519\0\0\0 ", 19)
	   ) return DROPBEAR_FAILURE;
	memset(key->spk, '\0', 32);  /* Secret key not known. */
	memcpy(key->spk + 32, buf->data + buf->pos + 19, 32);
	buf->pos += 51;
	return DROPBEAR_SUCCESS;
}

/* Loads a private ed25519 key from a buffer
 * Returns DROPBEAR_SUCCESS or DROPBEAR_FAILURE */
int buf_get_ed25519_priv_key(buffer* buf, dropbear_ed25519_key *key) {
	/* Format (not shared with OpenSSH):
	 *
	 * "\0\0\0\x0bssh-ed25519\0\0\0@" + sk + pk,
	 * where sk is 32 bytes of secret key (private key).
	 * where pk is 32 bytes of public key.
	 * It's 83 bytes in total.
	 */
	if (buf->pos + 83 > buf->len ||
	    0 != memcmp(buf->data + buf->pos, "\0\0\0\x0bssh-ed25519\0\0\0@", 19)
	   ) return DROPBEAR_FAILURE;
	memcpy(key->spk, buf->data + buf->pos + 19, 64);
	buf->pos += 83;
	return DROPBEAR_SUCCESS;
}
	

/* Clear and free the memory used by a public or private key */
void ed25519_key_free(dropbear_ed25519_key *key) {
	(void)key;
}

/* put the ed25519 public key into the buffer in the required format. */
void buf_put_ed25519_pub_key(buffer* buf, dropbear_ed25519_key *key) {
	dropbear_assert(key != NULL);
	buf_putstring(buf, SSH_SIGNKEY_ED25519, SSH_SIGNKEY_ED25519_LEN);
	buf_putstring(buf, key->spk + 32, 32);
}

/* put the ed25519 private key into the buffer in the required format. */
void buf_put_ed25519_priv_key(buffer* buf, dropbear_ed25519_key *key) {
	dropbear_assert(key != NULL);
	buf_putstring(buf, SSH_SIGNKEY_ED25519, SSH_SIGNKEY_ED25519_LEN);
	buf_putstring(buf, key->spk, 64);
}

#ifdef DROPBEAR_SIGNKEY_VERIFY
/* Verify a ed25519 signature (in buf) made on data by the key given.
 * returns DROPBEAR_SUCCESS or DROPBEAR_FAILURE */
int buf_ed25519_verify(buffer* buf, dropbear_ed25519_key *key, buffer *data_buf) {
	char sm[512];
	int res;
	/* Typical data_size is 148 bytes for ssh. */
	unsigned data_size;
	if (buf_getint(buf) != 64 ||
	    buf->len - buf->pos != 64 ||
	    (data_size = data_buf->len) > 512 - 64) {
		return DROPBEAR_FAILURE;
	}
	memcpy(sm, buf->data + buf->pos, 64);
	memcpy(sm + 64, data_buf->data, data_size);
	res = crypto_sign_open_m(sm, data_size + 64, key->spk + 32);
	return res ? DROPBEAR_FAILURE : DROPBEAR_SUCCESS;
}
#endif /* DROPBEAR_SIGNKEY_VERIFY */

/* Sign the data presented with key, writing the signature contents
 * to buf */
void buf_put_ed25519_sign(buffer* buf, dropbear_ed25519_key *key, buffer *data_buf) {
	char sm[128];
	/* Typical data_size is 32 bytes for ssh. */
	unsigned data_size = data_buf->len;
	if (data_size > 64) dropbear_exit("ed25519 message to sign too long");
	crypto_sign_m(sm, data_buf->data, data_size, key->spk);
	buf_putstring(buf, SSH_SIGNKEY_ED25519, SSH_SIGNKEY_ED25519_LEN);
	buf_putstring(buf, sm, 64);
}

#endif /* DROPBEAR_ED25519 */
