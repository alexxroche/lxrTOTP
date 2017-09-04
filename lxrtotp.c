#include <string.h>
#include <ctype.h> //isalpha, toupper
#include <time.h> //time_t
#include <stdlib.h> //exit
#include <stdio.h> //sprintf, stdout
#include <stdint.h> //uint32_t
#include <stddef.h>
void * memxor (void */*restrict*/ dest, const void */*restrict*/ src, size_t n){
  char const *s = (char const*)src; char *d = (char*)dest;
  for (; n > 0; n--)
    *d++ ^= *s++;
  return dest;
}
struct sha1_ctx {
  uint32_t A,B,C,D,E; uint32_t total[2]; uint32_t buflen; uint32_t buffer[32];
};
extern void sha1_init_ctx (struct sha1_ctx *ctx);
extern void sha1_process_block (const void *buffer, size_t len,
				struct sha1_ctx *ctx);
extern void sha1_process_bytes (const void *buffer, size_t len,
				struct sha1_ctx *ctx);
extern void *sha1_finish_ctx (struct sha1_ctx *ctx, void *resbuf);
extern void *sha1_read_ctx (const struct sha1_ctx *ctx, void *resbuf);
extern void *sha1_buffer (const char *buffer, size_t len, void *resblock);
#ifdef WORDS_BIGENDIAN
# define SWAP(n) (n)
#else
# define SWAP(n) \
    (((n) << 24) | (((n) & 0xff00) << 8) | (((n) >> 8) & 0xff00) | ((n) >> 24))
#endif
static const unsigned char fillbuf[64] = { 0x80, 0 /* , 0, 0, ...  */ };
void sha1_init_ctx (struct sha1_ctx *ctx) {
  ctx->A = 0x67452301; ctx->B = 0xefcdab89; ctx->C = 0x98badcfe;
  ctx->D = 0x10325476; ctx->E = 0xc3d2e1f0;
  ctx->total[0] = ctx->total[1] = 0; ctx->buflen = 0;
}
static __inline__ void set_uint32(char *cp, uint32_t v){memcpy(cp,&v,sizeof v);}
void * sha1_read_ctx (const struct sha1_ctx *ctx, void *resbuf){
  char *r = (char*)resbuf;
  set_uint32 (r + 0 * sizeof ctx->A, SWAP (ctx->A));
  set_uint32 (r + 1 * sizeof ctx->B, SWAP (ctx->B));
  set_uint32 (r + 2 * sizeof ctx->C, SWAP (ctx->C));
  set_uint32 (r + 3 * sizeof ctx->D, SWAP (ctx->D));
  set_uint32 (r + 4 * sizeof ctx->E, SWAP (ctx->E));
  return resbuf;
}
void * sha1_finish_ctx (struct sha1_ctx *ctx, void *resbuf) {
  uint32_t bytes = ctx->buflen;
  size_t size = (bytes < 56) ? 64 / 4 : 64 * 2 / 4;
  ctx->total[0] += bytes;
  if (ctx->total[0] < bytes)
    ++ctx->total[1];
  ctx->buffer[size - 2] = SWAP ((ctx->total[1] << 3) | (ctx->total[0] >> 29));
  ctx->buffer[size - 1] = SWAP (ctx->total[0] << 3);
  memcpy (&((char *) ctx->buffer)[bytes], fillbuf, (size - 2) * 4 - bytes);
  sha1_process_block (ctx->buffer, size * 4, ctx);
  return sha1_read_ctx (ctx, resbuf);
}
void * sha1_buffer (const char *buffer, size_t len, void *resblock) {
  struct sha1_ctx ctx; sha1_init_ctx (&ctx);
  sha1_process_bytes (buffer, len, &ctx);
  return sha1_finish_ctx (&ctx, resblock);
}
void sha1_process_bytes (const void *buffer, size_t len, struct sha1_ctx *ctx) {
  if (ctx->buflen != 0){
    size_t left_over = ctx->buflen;
    size_t add = 128 - left_over > len ? len : 128 - left_over;
    memcpy (&((char *) ctx->buffer)[left_over], buffer, add);
    ctx->buflen += add;
    if (ctx->buflen > 64){
	  sha1_process_block (ctx->buffer, ctx->buflen & ~63, ctx);
	  ctx->buflen &= 63;
	  memcpy (ctx->buffer,
		  &((char *) ctx->buffer)[(left_over + add) & ~63],
		  ctx->buflen);
	}
    buffer = (const char *) buffer + add; len -= add;
  }
  if (len >= 64){
#if !_STRING_ARCH_unaligned
# define alignof(type) offsetof (struct { char c; type x; }, x)
# define UNALIGNED_P(p) (((size_t) p) % alignof (uint32_t) != 0)
    if (UNALIGNED_P (buffer))
	while (len > 64) {
	    sha1_process_block (memcpy (ctx->buffer, buffer, 64), 64, ctx);
	    buffer = (const char *) buffer + 64; len -= 64;
	  }else
#endif
	{
	  sha1_process_block (buffer, len & ~63, ctx);
	  buffer = (const char *) buffer + (len & ~63); len &= 63;
	}
  }
  if (len > 0){ size_t left_over = ctx->buflen;
    memcpy (&((char *) ctx->buffer)[left_over], buffer, len);
    left_over += len;
    if (left_over >= 64){
	  sha1_process_block (ctx->buffer, 64, ctx); left_over -= 64;
	  memcpy (ctx->buffer, &ctx->buffer[16], left_over);
	}
    ctx->buflen = left_over;
  }
}
#define K1 0x5a827999
#define K2 0x6ed9eba1
#define K3 0x8f1bbcdc
#define K4 0xca62c1d6
#define F1(B,C,D) ( D ^ ( B & ( C ^ D ) ) )
#define F2(B,C,D) (B ^ C ^ D)
#define F3(B,C,D) ( ( B & C ) | ( D & ( B | C ) ) )
#define F4(B,C,D) (B ^ C ^ D)

void sha1_process_block (const void *buffer, size_t len, struct sha1_ctx *ctx){
  const uint32_t *words = (const uint32_t*)buffer;
  size_t nwords = len / sizeof (uint32_t);const uint32_t *endp = words + nwords;
  uint32_t x[16]; uint32_t a = ctx->A; uint32_t b = ctx->B; uint32_t c = ctx->C;
  uint32_t d = ctx->D; uint32_t e = ctx->E;
  ctx->total[0] += len;
  if (ctx->total[0] < len)
    ++ctx->total[1];
#define rol(x, n) (((x) << (n)) | ((uint32_t) (x) >> (32 - (n))))
#define M(I)(tm=x[I&0x0f]^x[(I-14)&0x0f]^x[(I-8)&0x0f]^x[(I-3)&0x0f],(x[I&0x0f]=rol(tm,1)))
#define R(A,B,C,D,E,F,K,M) do{E+=rol(A,5)+F(B,C,D)+K+M; B=rol(B,30);} while(0)
  while (words < endp){
      uint32_t tm; int t; for(t=0;t<16;t++){x[t]=SWAP (*words); words++;}
      R( a, b, c, d, e, F1, K1, x[ 0] ); R( e, a, b, c, d, F1, K1, x[ 1] );
      R( d, e, a, b, c, F1, K1, x[ 2] ); R( c, d, e, a, b, F1, K1, x[ 3] );
      R( b, c, d, e, a, F1, K1, x[ 4] ); R( a, b, c, d, e, F1, K1, x[ 5] );
      R( e, a, b, c, d, F1, K1, x[ 6] ); R( d, e, a, b, c, F1, K1, x[ 7] );
      R( c, d, e, a, b, F1, K1, x[ 8] ); R( b, c, d, e, a, F1, K1, x[ 9] );
      R( a, b, c, d, e, F1, K1, x[10] ); R( e, a, b, c, d, F1, K1, x[11] );
      R( d, e, a, b, c, F1, K1, x[12] ); R( c, d, e, a, b, F1, K1, x[13] );
      R( b, c, d, e, a, F1, K1, x[14] ); R( a, b, c, d, e, F1, K1, x[15] );
      R( e, a, b, c, d, F1, K1, M(16) ); R( d, e, a, b, c, F1, K1, M(17) );
      R( c, d, e, a, b, F1, K1, M(18) ); R( b, c, d, e, a, F1, K1, M(19) );
      R( a, b, c, d, e, F2, K2, M(20) ); R( e, a, b, c, d, F2, K2, M(21) );
      R( d, e, a, b, c, F2, K2, M(22) ); R( c, d, e, a, b, F2, K2, M(23) );
      R( b, c, d, e, a, F2, K2, M(24) ); R( a, b, c, d, e, F2, K2, M(25) );
      R( e, a, b, c, d, F2, K2, M(26) ); R( d, e, a, b, c, F2, K2, M(27) );
      R( c, d, e, a, b, F2, K2, M(28) ); R( b, c, d, e, a, F2, K2, M(29) );
      R( a, b, c, d, e, F2, K2, M(30) ); R( e, a, b, c, d, F2, K2, M(31) );
      R( d, e, a, b, c, F2, K2, M(32) ); R( c, d, e, a, b, F2, K2, M(33) );
      R( b, c, d, e, a, F2, K2, M(34) ); R( a, b, c, d, e, F2, K2, M(35) );
      R( e, a, b, c, d, F2, K2, M(36) ); R( d, e, a, b, c, F2, K2, M(37) );
      R( c, d, e, a, b, F2, K2, M(38) ); R( b, c, d, e, a, F2, K2, M(39) );
      R( a, b, c, d, e, F3, K3, M(40) ); R( e, a, b, c, d, F3, K3, M(41) );
      R( d, e, a, b, c, F3, K3, M(42) ); R( c, d, e, a, b, F3, K3, M(43) );
      R( b, c, d, e, a, F3, K3, M(44) ); R( a, b, c, d, e, F3, K3, M(45) );
      R( e, a, b, c, d, F3, K3, M(46) ); R( d, e, a, b, c, F3, K3, M(47) );
      R( c, d, e, a, b, F3, K3, M(48) ); R( b, c, d, e, a, F3, K3, M(49) );
      R( a, b, c, d, e, F3, K3, M(50) ); R( e, a, b, c, d, F3, K3, M(51) );
      R( d, e, a, b, c, F3, K3, M(52) ); R( c, d, e, a, b, F3, K3, M(53) );
      R( b, c, d, e, a, F3, K3, M(54) ); R( a, b, c, d, e, F3, K3, M(55) );
      R( e, a, b, c, d, F3, K3, M(56) ); R( d, e, a, b, c, F3, K3, M(57) );
      R( c, d, e, a, b, F3, K3, M(58) ); R( b, c, d, e, a, F3, K3, M(59) );
      R( a, b, c, d, e, F4, K4, M(60) ); R( e, a, b, c, d, F4, K4, M(61) );
      R( d, e, a, b, c, F4, K4, M(62) ); R( c, d, e, a, b, F4, K4, M(63) );
      R( b, c, d, e, a, F4, K4, M(64) ); R( a, b, c, d, e, F4, K4, M(65) );
      R( e, a, b, c, d, F4, K4, M(66) ); R( d, e, a, b, c, F4, K4, M(67) );
      R( c, d, e, a, b, F4, K4, M(68) ); R( b, c, d, e, a, F4, K4, M(69) );
      R( a, b, c, d, e, F4, K4, M(70) ); R( e, a, b, c, d, F4, K4, M(71) );
      R( d, e, a, b, c, F4, K4, M(72) ); R( c, d, e, a, b, F4, K4, M(73) );
      R( b, c, d, e, a, F4, K4, M(74) ); R( a, b, c, d, e, F4, K4, M(75) );
      R( e, a, b, c, d, F4, K4, M(76) ); R( d, e, a, b, c, F4, K4, M(77) );
      R( c, d, e, a, b, F4, K4, M(78) ); R( b, c, d, e, a, F4, K4, M(79) );
      a= ctx->A += a;b= ctx->B += b;c= ctx->C +=c;d= ctx->D +=d;e= ctx->E +=e;
    }
}
#define IPAD 0x36
#define OPAD 0x5c
int hmac_sha1 (const void *key, size_t keylen,
	   const void *in, size_t inlen, void *resbuf){
  struct sha1_ctx inner, outer; char optkeybuf[20],block[64],innerhash[20];
  if (keylen > 64){
      struct sha1_ctx keyhash; sha1_init_ctx (&keyhash);
      sha1_process_bytes (key, keylen, &keyhash);
      sha1_finish_ctx (&keyhash, optkeybuf);
      key = optkeybuf; keylen = 20;
  }
  sha1_init_ctx (&inner);
  memset (block, IPAD, sizeof (block)); memxor (block, key, keylen);
  sha1_process_block (block, 64, &inner);sha1_process_bytes (in, inlen, &inner);
  sha1_finish_ctx (&inner, innerhash);sha1_init_ctx (&outer);
  memset (block, OPAD, sizeof (block)); memxor (block, key, keylen);
  sha1_process_block(block,64,&outer);sha1_process_bytes(innerhash,20,&outer);
  sha1_finish_ctx (&outer, resbuf); return 0;
}
int b32decode(const char *s, unsigned char *b) {
    int i; memset(b, 0, 10);
    for (i = 0; i < 16; i++){
        unsigned char x; if (isalpha(s[i])){ x = toupper(s[i]) - 'A';}
        else if (s[i] >= '2' && s[i] <= '7'){ x = s[i] - '2' + 26;}
        else{return 0;} b[5*i / 8] |= (x << 3) >> (5*i % 8);
        if (5*i % 8 >= 4){ b[5*i / 8 + 1] |= x << (3 + 8 - (5*i % 8));}
    } return 1;
}
void hotp(const unsigned char *sbytes, time_t movingFactor, char *code){
    unsigned char data[8]; int i, offset, bin_code, otp;
    for (i=0;i<8;i++){data[i] = i<4 ? 0 : movingFactor >> (56 - 8*i);}
    unsigned char resbuf[20]; unsigned char *r = resbuf;
    hmac_sha1(sbytes,sizeof(sbytes)+2,data,sizeof(data),r);offset=r[19]&0xf;
    bin_code = ((r[offset] << 24) | (r[offset+1] << 16) | (r[offset+2] << 8) | r[offset+3]) & 0x7fffffff;
    otp = bin_code % 1000000; sprintf(code, "%06d", otp);
}
int main(int argc, char *argv[]) {
    unsigned char sbytes[10]; char code[7]; time_t now; if (argc < 2){exit(1);}
    if (!b32decode(argv[1], sbytes)){exit(1);}
    now = time(NULL); hotp(sbytes, now / 30, code); fprintf(stdout, code);
}
