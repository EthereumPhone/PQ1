/* Probe: plain C SHA-512 compression (FIPS 180-4), GCC -O2 -mcpu=cortex-m33, to bound what a 32-bit core
 * can do. bench_run: 2,000 compressions, cycles per block in user[0]; first state word checked against a
 * host reference in user[1..2] (hi, lo). */
#include <stdint.h>
#include "bench.h"
__attribute__((used)) uint8_t SIG0[4008], SIG1[4008];
static const uint64_t K[80] = {
0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL};
#ifndef COMPRESS
#define COMPRESS sha512_compress
#endif
#define ROR(x,n) (((x)>>(n))|((x)<<(64-(n))))
#define S0(x) (ROR(x,28)^ROR(x,34)^ROR(x,39))
#define S1(x) (ROR(x,14)^ROR(x,18)^ROR(x,41))
#define s0(x) (ROR(x,1)^ROR(x,8)^((x)>>7))
#define s1(x) (ROR(x,19)^ROR(x,61)^((x)>>6))
__attribute__((noinline)) void sha512_compress(uint64_t st[8], const uint64_t in[16]) {
  uint64_t w[16]; for (int i = 0; i < 16; i++) w[i] = in[i];
  uint64_t a=st[0],b=st[1],c=st[2],d=st[3],e=st[4],f=st[5],g=st[6],h=st[7];
  for (int r = 0; r < 80; r++) {
    if (r >= 16) { int j = r & 15; w[j] += s1(w[(j+14)&15]) + w[(j+9)&15] + s0(w[(j+1)&15]); }
    uint64_t t1 = h + S1(e) + (g ^ (e & (f ^ g))) + K[r] + w[r & 15];
    uint64_t t2 = S0(a) + ((a & b) | (c & (a | b)));
    h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
  }
  st[0]+=a; st[1]+=b; st[2]+=c; st[3]+=d; st[4]+=e; st[5]+=f; st[6]+=g; st[7]+=h;
}

/* Variant B: state as 32-bit halves, Sigma on halves, 64-bit adds via uint64 (adds/adc). */
#define H(x) ((uint32_t)((x) >> 32))
#define L(x) ((uint32_t)(x))
#define J(h,l) (((uint64_t)(h) << 32) | (l))
static inline uint64_t S0h(uint64_t x){uint32_t h=H(x),l=L(x);return J((h>>28|l<<4)^(l>>2|h<<30)^(l>>7|h<<25),(l>>28|h<<4)^(h>>2|l<<30)^(h>>7|l<<25));}
static inline uint64_t S1h(uint64_t x){uint32_t h=H(x),l=L(x);return J((h>>14|l<<18)^(h>>18|l<<14)^(l>>9|h<<23),(l>>14|h<<18)^(l>>18|h<<14)^(h>>9|l<<23));}
static inline uint64_t s0h(uint64_t x){uint32_t h=H(x),l=L(x);return J((h>>1|l<<31)^(h>>8|l<<24)^(h>>7),(l>>1|h<<31)^(l>>8|h<<24)^(l>>7|h<<25));}
static inline uint64_t s1h(uint64_t x){uint32_t h=H(x),l=L(x);return J((h>>19|l<<13)^(l>>29|h<<3)^(h>>6),(l>>19|h<<13)^(h>>29|l<<3)^(l>>6|h<<26));}
#define RND(a,b,c,d,e,f,g,h,i,r) do { \
  if ((r) >= 16) { int j = (i); w[j] += s1h(w[(j+14)&15]) + w[(j+9)&15] + s0h(w[(j+1)&15]); } \
  uint64_t t1 = h + S1h(e) + (g ^ (e & (f ^ g))) + K[r] + w[i]; \
  uint64_t t2 = S0h(a) + ((a & b) | (c & (a | b))); d += t1; h = t1 + t2; } while (0)
#define SIX(B) RND(a,b,c,d,e,f,g,h,0,B);RND(h,a,b,c,d,e,f,g,1,B+1);RND(g,h,a,b,c,d,e,f,2,B+2);RND(f,g,h,a,b,c,d,e,3,B+3);\
 RND(e,f,g,h,a,b,c,d,4,B+4);RND(d,e,f,g,h,a,b,c,5,B+5);RND(c,d,e,f,g,h,a,b,6,B+6);RND(b,c,d,e,f,g,h,a,7,B+7);\
 RND(a,b,c,d,e,f,g,h,8,B+8);RND(h,a,b,c,d,e,f,g,9,B+9);RND(g,h,a,b,c,d,e,f,10,B+10);RND(f,g,h,a,b,c,d,e,11,B+11);\
 RND(e,f,g,h,a,b,c,d,12,B+12);RND(d,e,f,g,h,a,b,c,13,B+13);RND(c,d,e,f,g,h,a,b,14,B+14);RND(b,c,d,e,f,g,h,a,15,B+15)
__attribute__((noinline)) void sha512_compress_b(uint64_t st[8], const uint64_t in[16]) {
  uint64_t w[16]; for (int i = 0; i < 16; i++) w[i] = in[i];
  uint64_t a=st[0],b=st[1],c=st[2],d=st[3],e=st[4],f=st[5],g=st[6],h=st[7];
  SIX(0); SIX(16); SIX(32); SIX(48); SIX(64);
  st[0]+=a; st[1]+=b; st[2]+=c; st[3]+=d; st[4]+=e; st[5]+=f; st[6]+=g; st[7]+=h;
}

void c10_bench_main(void) {
  uint64_t st[8] = {0x6a09e667f3bcc908ULL,0xbb67ae8584caa73bULL,0x3c6ef372fe94f82bULL,0xa54ff53a5f1d36f1ULL,0x510e527fade682d1ULL,0x9b05688c2b3e6c1fULL,0x1f83d9abfb41bd6bULL,0x5be0cd19137e2179ULL};
  uint64_t blk[16]; for (int i = 0; i < 16; i++) blk[i] = 0x0123456789abcdefULL * (uint64_t)(i + 1);
  uint32_t t = bench_cyc();
  for (int n = 0; n < 2000; n++) { COMPRESS(st, blk); blk[0] ^= st[0]; }
  BENCH.user[0] = (bench_cyc() - t) / 2000;
  ((volatile uint8_t *)SIG0)[0] = 1; ((volatile uint8_t *)SIG1)[0] = 1;
  BENCH.user[1] = (uint32_t)(st[0] >> 32); BENCH.user[2] = (uint32_t)st[0];
}
