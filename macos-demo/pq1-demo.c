/*
 * PQ1 Demo for macOS: the android-demo flows in a Terminal menu, for a conference booth.
 *
 * Plug in PQ1, unlock it, press a key: PQ1 clear-signs the demo transaction on its own screen.
 * Nothing is broadcast; signatures never leave this process.
 *
 * A C port of android-demo/app/src/main/java/io/freedomfactory/pq1demo (core/Bytes, Keccak, Wire,
 * Flows, Apdu, Pq1 and the DemoViewModel loop). `--selftest <dir>` holds every request
 * byte-identical to android-demo's goldens, which come from tools/demo_px_flows.py.
 *
 * No dependencies: the binary links libSystem only and loads IOKit + CoreFoundation with dlopen,
 * so it cross-compiles from Linux with `zig cc` and needs no macOS SDK. The hidraw backend runs
 * the same program against a PQ1 on a Linux bench. build.sh embeds the ERC-20 proofs.
 */
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define PQ1_VID 0x1209
#define PQ1_PID 0x7051

static __attribute__((noreturn, format(printf, 1, 2))) void die(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(2);
}

static long now_ms(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000L + t.tv_nsec / 1000000L;
}

/* ── bytes (core/Bytes.kt) ─────────────────────────────────────────────────────────────── */

#define CAP 16384 /* largest message: a sign reply is at most 12,620 B */

typedef struct { size_t n; uint8_t b[CAP]; } Buf;
typedef struct { uint8_t b[20]; } Addr;
typedef struct { uint8_t b[32]; } U256; /* big-endian */

static const U256 ZERO;

static void put(Buf *o, const void *p, size_t n)
{
    if (n > CAP - o->n) die("internal: message over %d B", CAP);
    if (n) memcpy(o->b + o->n, p, n);
    o->n += n;
}

static void put_u8(Buf *o, unsigned v)
{
    uint8_t b = (uint8_t)v;
    put(o, &b, 1);
}

/* Big-endian in `len` bytes: u16/u32/u64 in Bytes.kt. */
static void put_be(Buf *o, uint64_t v, int len)
{
    for (int i = len - 1; i >= 0; i--) put_u8(o, (unsigned)(v >> (8 * i)) & 0xFF);
}

static void put_zeros(Buf *o, size_t n)
{
    static const uint8_t z[32];
    while (n) {
        size_t k = n < sizeof z ? n : sizeof z;
        put(o, z, k);
        n -= k;
    }
}

static void put_word(Buf *o, uint64_t v) /* u256(Long) */
{
    put_zeros(o, 24);
    put_be(o, v, 8);
}

static void put_u256(Buf *o, const U256 *v) { put(o, v->b, 32); }
static void put_addr(Buf *o, Addr a) { put(o, a.b, 20); }
static void put_buf(Buf *o, const Buf *b) { put(o, b->b, b->n); }

static void put_word_addr(Buf *o, Addr a) /* wordAddr */
{
    put_zeros(o, 12);
    put_addr(o, a);
}

static void set_be(uint8_t *p, uint64_t v, int len)
{
    for (int i = 0; i < len; i++) p[len - 1 - i] = (uint8_t)(v >> (8 * i));
}

static void set_word(uint8_t *p, uint64_t v)
{
    memset(p, 0, 24);
    set_be(p + 24, v, 8);
}

/* beLong: big-endian, keeps the low 64 bits. */
static uint64_t be(const uint8_t *p, size_t len)
{
    uint64_t v = 0;
    for (size_t i = 0; i < len; i++) v = v << 8 | p[i];
    return v;
}

static void hex(char *out, const uint8_t *p, size_t n)
{
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = d[p[i] >> 4];
        out[2 * i + 1] = d[p[i] & 15];
    }
    out[2 * n] = 0;
}

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Copy `s` without leading and trailing whitespace. */
static void trim(char *out, size_t n, const char *s)
{
    while (isspace((unsigned char)*s)) s++;
    size_t k = strlen(s);
    while (k && isspace((unsigned char)s[k - 1])) k--;
    if (k >= n) k = n - 1;
    memcpy(out, s, k);
    out[k] = 0;
}

/* A 20-byte address from "0x…" hex: NULL, else the reason. */
static const char *parse_addr(const char *s, Addr *a)
{
    char t[128];
    trim(t, sizeof t, s);
    const char *h = t[0] == '0' && (t[1] == 'x' || t[1] == 'X') ? t + 2 : t;
    if (strlen(h) != 40) return "not a 20-byte hex address";
    for (int i = 0; i < 20; i++) {
        int hi = hexval(h[2 * i]), lo = hexval(h[2 * i + 1]);
        if (hi < 0 || lo < 0) return "not a 20-byte hex address";
        a->b[i] = (uint8_t)(hi << 4 | lo);
    }
    return NULL;
}

static Addr A(const char *s) /* a constant address */
{
    Addr a;
    if (parse_addr(s, &a)) die("internal: bad address %s", s);
    return a;
}

/* A human decimal ("1,234.56") in base units with `decimals` places: NULL, else the reason
 * (parseUnits, plus the u256 range check Wire applies when it encodes). */
static const char *parse_units(const char *text, int decimals, U256 *out)
{
    static char why[40];
    char t[128];
    size_t n = 0;
    trim(t, sizeof t, text);
    for (const char *p = t; *p; p++)
        if (*p != ',' && *p != '_') t[n++] = *p;
    t[n] = 0;
    const char *dot = strchr(t, '.');
    size_t whole = dot ? (size_t)(dot - t) : n, frac = dot ? n - whole - 1 : 0;
    bool ok = whole + frac > 0;
    for (size_t i = 0; i < n; i++)
        if (!isdigit((unsigned char)t[i]) && t + i != dot) ok = false;
    if (!ok) return "not a number";
    if (frac > (size_t)decimals) {
        snprintf(why, sizeof why, "at most %d decimals", decimals);
        return why;
    }
    memset(out, 0, sizeof *out);
    for (size_t i = 0; i < n + ((size_t)decimals - frac); i++) {
        if (i < n && t[i] == '.') continue;
        unsigned carry = i < n ? (unsigned)(t[i] - '0') : 0;
        for (int j = 31; j >= 0; j--) {
            unsigned x = out->b[j] * 10u + carry;
            out->b[j] = (uint8_t)x;
            carry = x >> 8;
        }
        if (carry) return "u256 out of range";
    }
    return NULL;
}

/* ── Keccak-256 (core/Keccak.kt: Ethereum's 0x01 padding, not SHA3's 0x06) and SHA-256 ──── */

static uint64_t rol64(uint64_t x, int n) { return n ? x << n | x >> (64 - n) : x; }

static void keccak_f(uint64_t s[25])
{
    static const uint64_t RC[24] = {
        0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808AULL, 0x8000000080008000ULL,
        0x000000000000808BULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
        0x000000000000008AULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000AULL,
        0x000000008000808BULL, 0x800000000000008BULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
        0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800AULL, 0x800000008000000AULL,
        0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
    };
    static const int R[25] = { /* rotation offsets indexed by x + 5y */
        0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
    };
    uint64_t c[5], b[25];
    for (int round = 0; round < 24; round++) {
        for (int x = 0; x < 5; x++) c[x] = s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20];
        for (int x = 0; x < 5; x++) {
            uint64_t d = c[(x + 4) % 5] ^ rol64(c[(x + 1) % 5], 1);
            for (int y = 0; y < 5; y++) s[x + 5 * y] ^= d;
        }
        for (int x = 0; x < 5; x++)
            for (int y = 0; y < 5; y++) b[y + 5 * ((2 * x + 3 * y) % 5)] = rol64(s[x + 5 * y], R[x + 5 * y]);
        for (int x = 0; x < 5; x++)
            for (int y = 0; y < 5; y++)
                s[x + 5 * y] = b[x + 5 * y] ^ (~b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y]);
        s[0] ^= RC[round];
    }
}

static void keccak256(const void *in, size_t n, uint8_t out[32])
{
    enum { RATE = 136 };
    const uint8_t *p = in;
    uint64_t s[25] = { 0 };
    uint8_t last[RATE];
    for (;;) {
        const uint8_t *blk = p;
        if (n < RATE) { /* the final block, with 0x01 … 0x80 padding */
            memset(last, 0, RATE);
            if (n) memcpy(last, p, n);
            last[n] ^= 0x01;
            last[RATE - 1] ^= 0x80;
            blk = last;
        }
        for (int i = 0; i < RATE / 8; i++) {
            uint64_t w = 0;
            for (int j = 7; j >= 0; j--) w = w << 8 | blk[8 * i + j];
            s[i] ^= w;
        }
        keccak_f(s);
        if (blk == last) break;
        p += RATE;
        n -= RATE;
    }
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 8; j++) out[8 * i + j] = (uint8_t)(s[i] >> (8 * j));
}

static void keccak_str(const char *s, uint8_t out[32]) { keccak256(s, strlen(s), out); }
static void keccak_buf(const Buf *b, uint8_t out[32]) { keccak256(b->b, b->n, out); }

static const uint32_t SHA256_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static uint32_t ror32(uint32_t x, int n) { return x >> n | x << (32 - n); }

static void sha256_block(uint32_t h[8], const uint8_t *p)
{
    uint32_t w[64];
    for (int i = 0; i < 16; i++) w[i] = (uint32_t)be(p + 4 * i, 4);
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ror32(w[i - 15], 7) ^ ror32(w[i - 15], 18) ^ w[i - 15] >> 3;
        uint32_t s1 = ror32(w[i - 2], 17) ^ ror32(w[i - 2], 19) ^ w[i - 2] >> 10;
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], k = h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = k + (ror32(e, 6) ^ ror32(e, 11) ^ ror32(e, 25)) + ((e & f) ^ (~e & g)) + SHA256_K[i] + w[i];
        uint32_t t2 = (ror32(a, 2) ^ ror32(a, 13) ^ ror32(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        k = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
    h[5] += f;
    h[6] += g;
    h[7] += k;
}

static void sha256(const void *in, size_t n, uint8_t out[32])
{
    uint32_t h[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
    const uint8_t *m = in;
    uint8_t last[128] = { 0 };
    size_t i = 0;
    for (; i + 64 <= n; i += 64) sha256_block(h, m + i);
    size_t r = n - i, len = r + 9 <= 64 ? 64 : 128;
    if (r) memcpy(last, m + i, r);
    last[r] = 0x80;
    set_be(last + len - 8, (uint64_t)n * 8, 8);
    sha256_block(h, last);
    if (len == 128) sha256_block(h, last + 64);
    for (int j = 0; j < 8; j++) set_be(out + 4 * j, h[j], 4);
}

/* ── wire (core/Wire.kt, a port of tools/demo_px_flows.py) ─────────────────────────────── */

/* APDU v2 instructions (nonsecure/src/usb/commands.rs) and status words. */
enum { INS_GET_STATUS = 0x02, INS_LOCK = 0x11, INS_SIGN_USEROP = 0x30, INS_GET_WALLET_ADDRESS = 0x60 };
enum {
    SW_OK = 0x9000,
    SW_DECLINED = 0x6982,   /* UserRejected (hold-left on the device) */
    SW_IDLE_WIPED = 0x6984, /* 120 s idle timer fired during the ask */
    SW_NOT_READY = 0x6985,  /* locked / off-chain gate / fw-update state */
};

#define C10_SIG_LEN 4008
#define SIG_WRAPPER_LEN (32 + 32 + 32 + 4032) /* 4128 */
#define SAFE_NONCE_BASE 17

#define CHAIN_BASE 8453
#define CHAIN_MAINNET 1

static const char ENTRY_POINT_V06[] = "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789";
static const char USDC_BASE[] = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
static const char WETH_BASE[] = "0x4200000000000000000000000000000000000006";
static const char DAI_BASE[] = "0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb";
static const char WETH_MAINNET[] = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";
static const char USDC_MAINNET[] = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
static const char GPV2_SETTLEMENT[] = "0x9008D19f58AAbD9eD0D60971565AA8510560ab41";
static const char VAULT_RELAYER[] = "0xC92E8bdf79f0507f65a392b0ab4667716BFE0110";
static const char MULTISEND_CALL_ONLY_V150[] = "0xA83c336B20401aF773B6219BA5027174338D1836";
static const char DEMO_SAFE[] = "0x5E7708eb2B75AC5005FDdCfCa67efA8251a0732F";
/* Random, EIP-55 checksummed demo addresses (no known owner). */
static const char ALICE[] = "0xbD547DBAA2fdBc03B3a5F2d900100DB317CE9abB";
static const char BOB[] = "0xb7A2754cda372E8625CeF80F87eD11d784dA3408";
/* demo_bybit_replay.py: the SafeTx Bybit's signers approved on 2025-02-21. */
static const char BYBIT_SAFE[] = "0x1Db92e2EeBC8E0c075a02BeA49a2935BcD2dFCF4";
static const char BYBIT_ATTACKER[] = "0x96221423681A6d52E184D440a8eFCEbB105C7242";
static const char BYBIT_SWEEPER[] = "0xbDd077f651EBe7f7b3cE16fe5F2b025BE2969516";

static const uint8_t TRANSFER[4] = { 0xa9, 0x05, 0x9c, 0xbb };
static const uint8_t APPROVE[4] = { 0x09, 0x5e, 0xa7, 0xb3 };
static const uint8_t SET_PRESIGNATURE[4] = { 0xec, 0x6c, 0xb1, 0x3f };
static const uint8_t MULTI_SEND[4] = { 0x8d, 0x80, 0xff, 0x0a };
static const uint8_t APPROVE_HASH[4] = { 0xd4, 0xd9, 0xbd, 0xcd };

/* Gas words of every demo UserOp. */
enum { GAS_CALL = 120000, GAS_VER = 800000, GAS_PRE = 150000, GAS_MAX_FEE = 1000000000, GAS_PRIO = 100000000 };

/* Per-request inputs. `take` counts the requests sent: it is the UserOp nonce and offsets the
 * Safe nonce (17 + take), exactly as demo_px_flows.py does. */
typedef struct {
    Addr sender, safe;
    uint64_t take, valid_to;
    uint32_t flags;
} Ctx;

static void erc20_call(Buf *o, const uint8_t sel[4], Addr who, const U256 *amount)
{
    put(o, sel, 4);
    put_word_addr(o, who);
    put_u256(o, amount);
}

static void userop_head(Buf *o, Addr sender, uint64_t chain, uint32_t flags, uint64_t nonce, Addr to,
                        const U256 *value, const Buf *data)
{
    uint8_t sha256_empty[32];
    sha256("", 0, sha256_empty);
    put_be(o, chain, 8);
    put_be(o, flags, 4);
    put_addr(o, sender);
    put_addr(o, A(ENTRY_POINT_V06));
    put_word(o, nonce);
    put_word(o, GAS_CALL);
    put_word(o, GAS_VER);
    put_word(o, GAS_PRE);
    put_word(o, GAS_MAX_FEE);
    put_word(o, GAS_PRIO);
    put(o, sha256_empty, 32); /* paymaster_and_data_hash: no paymaster */
    put_addr(o, to);
    put_u256(o, value);
    put_be(o, data->n, 2);
    put_buf(o, data);
}

/* Positional trailers (cmd_sign_userop.rs): erc20 | reserved | cow | safe_v1 | selector | self_attest | erc7730. */
static void trailers(Buf *o, const Buf *erc20, const Buf *cow, const Buf *safe)
{
    const Buf *t[7] = { erc20, NULL, cow, safe, NULL, NULL, NULL };
    for (int i = 0; i < 7; i++) {
        put_be(o, t[i] ? t[i]->n : 0, 2);
        if (t[i]) put_buf(o, t[i]);
    }
}

/* ── Safe (proto/src/lib.rs safe_v1 canonical, 281 B) ── */
enum {
    SAFE_LEN = 281,
    OFF_CHAIN = 0,
    OFF_SAFE = 8,
    OFF_TO = 28,
    OFF_VALUE = 48,
    OFF_DATA_HASH = 80,
    OFF_OPERATION = 112,
    OFF_SAFE_TX_GAS = 113,
    OFF_BASE_GAS = 145,
    OFF_GAS_PRICE = 177,
    OFF_GAS_TOKEN = 209,
    OFF_REFUND = 229,
    OFF_NONCE = 249,
};

static void safe_canonical(uint8_t c[SAFE_LEN], uint64_t chain, Addr safe, Addr to, const U256 *value,
                           const Buf *data, uint64_t nonce, int operation, uint64_t safe_tx_gas)
{
    memset(c, 0, SAFE_LEN);
    set_be(c + OFF_CHAIN, chain, 8);
    memcpy(c + OFF_SAFE, safe.b, 20);
    memcpy(c + OFF_TO, to.b, 20);
    memcpy(c + OFF_VALUE, value->b, 32);
    keccak_buf(data, c + OFF_DATA_HASH);
    c[OFF_OPERATION] = (uint8_t)operation;
    set_word(c + OFF_SAFE_TX_GAS, safe_tx_gas);
    set_word(c + OFF_NONCE, nonce);
}

static void safe_tx_hash(const uint8_t *c, uint8_t out[32])
{
    Buf b = { 0 };
    uint8_t th[32], domain[32], st[32];
    keccak_str("EIP712Domain(uint256 chainId,address verifyingContract)", th);
    put(&b, th, 32);
    put_zeros(&b, 24);
    put(&b, c + OFF_CHAIN, 8);
    put_zeros(&b, 12);
    put(&b, c + OFF_SAFE, 20);
    keccak_buf(&b, domain);
    b.n = 0;
    keccak_str("SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,"
               "uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)",
               th);
    put(&b, th, 32);
    put_zeros(&b, 12);
    put(&b, c + OFF_TO, 20);
    put(&b, c + OFF_VALUE, 32);
    put(&b, c + OFF_DATA_HASH, 32);
    put_zeros(&b, 31);
    put(&b, c + OFF_OPERATION, 1);
    put(&b, c + OFF_SAFE_TX_GAS, 32);
    put(&b, c + OFF_BASE_GAS, 32);
    put(&b, c + OFF_GAS_PRICE, 32);
    put_zeros(&b, 12);
    put(&b, c + OFF_GAS_TOKEN, 20);
    put_zeros(&b, 12);
    put(&b, c + OFF_REFUND, 20);
    put(&b, c + OFF_NONCE, 32);
    keccak_buf(&b, st);
    b.n = 0;
    put_u8(&b, 0x19);
    put_u8(&b, 0x01);
    put(&b, domain, 32);
    put(&b, st, 32);
    keccak_buf(&b, out);
}

/* `approveHash(safeTxHash)` on `safe` + the safe_v1 trailer carrying the full SafeTx. */
static void safe_approve_hash(Buf *o, const Ctx *c, uint64_t chain, Addr safe, const uint8_t *canonical,
                              const Buf *inner, const Buf *erc20, const Buf *cow)
{
    Buf data = { 0 }, st = { 0 };
    uint8_t h[32];
    safe_tx_hash(canonical, h);
    put(&data, APPROVE_HASH, 4);
    put(&data, h, 32);
    userop_head(o, c->sender, chain, c->flags, c->take, safe, &ZERO, &data);
    put(&st, canonical, SAFE_LEN);
    put_be(&st, inner->n, 2);
    put_buf(&st, inner);
    trailers(o, erc20, cow, &st);
}

/* ── Safe MultiSend ── */
static void multisend(Buf *o, const Buf *packed)
{
    put(o, MULTI_SEND, 4);
    put_word(o, 0x20);
    put_word(o, packed->n);
    put_buf(o, packed);
    put_zeros(o, (32 - packed->n % 32) % 32);
}

static void ms_record(Buf *o, Addr to, const Buf *data) /* op 0 (CALL) only, value 0 */
{
    put_u8(o, 0);
    put_addr(o, to);
    put_word(o, 0);
    put_word(o, data->n);
    put_buf(o, data);
}

/* ── CoW (secure/src/tx/eip712/cowswap; order canonical 204 B) ── */
enum { COW_LEN = 204 };

/* A SELL order; receiver 0 = the owner (the wallet, or the Safe when wrapped). */
static void cow_order(uint8_t o[COW_LEN], uint64_t chain, Addr sell, Addr buy, const U256 *sell_amount,
                      const U256 *buy_amount, uint64_t fee, uint64_t valid_to)
{
    memset(o, 0, COW_LEN);
    set_be(o, chain, 8);
    memcpy(o + 8, sell.b, 20);
    memcpy(o + 28, buy.b, 20);
    memcpy(o + 68, sell_amount->b, 32);
    memcpy(o + 100, buy_amount->b, 32);
    set_word(o + 132, fee);
    set_be(o + 164, valid_to, 4);
    o[168] = 0;                /* SELL */
    memset(o + 172, 0xa7, 32); /* appData */
}

static void cow_digest(const uint8_t *c, uint8_t out[32])
{
    Buf b = { 0 };
    uint8_t h[32], domain[32], st[32];
    keccak_str("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)", h);
    put(&b, h, 32);
    keccak_str("Gnosis Protocol", h);
    put(&b, h, 32);
    keccak_str("v2", h);
    put(&b, h, 32);
    put_zeros(&b, 24);
    put(&b, c, 8);
    put_word_addr(&b, A(GPV2_SETTLEMENT));
    keccak_buf(&b, domain);
    b.n = 0;
    keccak_str("Order(address sellToken,address buyToken,address receiver,uint256 sellAmount,"
               "uint256 buyAmount,uint32 validTo,bytes32 appData,uint256 feeAmount,string kind,"
               "bool partiallyFillable,string sellTokenBalance,string buyTokenBalance)",
               h);
    put(&b, h, 32);
    put_zeros(&b, 12);
    put(&b, c + 8, 20);
    put_zeros(&b, 12);
    put(&b, c + 28, 20);
    put_zeros(&b, 12);
    put(&b, c + 48, 20);
    put(&b, c + 68, 32);
    put(&b, c + 100, 32);
    put_zeros(&b, 28);
    put(&b, c + 164, 4);
    put(&b, c + 172, 32);
    put(&b, c + 132, 32);
    keccak_str(c[168] == 0 ? "sell" : "buy", h);
    put(&b, h, 32);
    put_zeros(&b, 31);
    put(&b, c + 169, 1);
    keccak_str(c[170] == 0 ? "erc20" : c[170] == 1 ? "external" : "internal", h);
    put(&b, h, 32);
    keccak_str(c[171] == 0 ? "erc20" : "internal", h);
    put(&b, h, 32);
    keccak_buf(&b, st);
    b.n = 0;
    put_u8(&b, 0x19);
    put_u8(&b, 0x01);
    put(&b, domain, 32);
    put(&b, st, 32);
    keccak_buf(&b, out);
}

/* `setPreSignature(orderUid, true)`; orderUid = digest | owner | validTo. */
static void presign(Buf *o, const uint8_t *order, Addr owner)
{
    uint8_t digest[32];
    cow_digest(order, digest);
    put(o, SET_PRESIGNATURE, 4);
    put_word(o, 0x40);
    put_word(o, 1);
    put_word(o, 56);
    put(o, digest, 32);
    put_addr(o, owner);
    put(o, order + 164, 4);
    put_zeros(o, 8);
}

/* ERC-20 Merkle proof bundles, cut from tools/companion-stub/erc20_db.bin by
 * android-demo/tools/gen_assets.py and embedded by build.sh. */
struct proof {
    uint64_t chain;
    const char *token; /* lowercase hex, no 0x */
    const unsigned char *data;
    unsigned len;
};
#include "proofs.h"

static const char *erc20_proof(uint64_t chain, Addr token, Buf *o)
{
    static char why[120];
    char h[41];
    hex(h, token.b, 20);
    for (size_t i = 0; i < sizeof PROOFS / sizeof PROOFS[0]; i++)
        if (PROOFS[i].chain == chain && !strcmp(PROOFS[i].token, h)) {
            put(o, PROOFS[i].data, PROOFS[i].len);
            return NULL;
        }
    snprintf(why, sizeof why, "no ERC-20 proof bundled for 0x%s on chain %llu", h, (unsigned long long)chain);
    return why;
}

/* Kind-3 order trailer with both legs' ERC-20 proofs, so the device decodes the legs. */
static const char *cow_trailer(Buf *o, const uint8_t *order)
{
    Buf sell = { 0 }, buy = { 0 };
    Addr a;
    const char *e;
    memcpy(a.b, order + 8, 20);
    if ((e = erc20_proof(be(order, 8), a, &sell))) return e;
    memcpy(a.b, order + 28, 20);
    if ((e = erc20_proof(be(order, 8), a, &buy))) return e;
    put(o, order, COW_LEN);
    put_be(o, sell.n, 2);
    put_buf(o, &sell);
    put_be(o, buy.n, 2);
    put_buf(o, &buy);
    return NULL;
}

/* ── flows (core/Flows.kt) ──────────────────────────────────────────────────────────────── */

/* What a correct device does with the request. */
typedef enum { EXPECT_SIGN, EXPECT_REFUSE, EXPECT_CONFIRM, EXPECT_LOCK } Expect;
typedef enum { REQ_USEROP, REQ_ADDRESS, REQ_LOCK } ReqKind;
typedef enum { FIELD_AMOUNT, FIELD_ADDRESS } FieldKind;

typedef struct {
    const char *key, *label, *def;
    FieldKind kind;
    int decimals;
    const char *suffix;
} Field;

typedef struct {
    int ins;
    ReqKind kind;
    Buf payload;
} Request;

typedef struct Flow Flow;
struct Flow {
    char key; /* menu key */
    const char *id, *group, *title, *blurb, *chain;
    Expect expect;
    const char *on_device[4];
    Field fields[2];
    const char *(*build)(const Flow *, const Ctx *, Request *); /* NULL, else why it can't */
    char value[2][100];                                         /* edited values; "" = the default */
};

static const char *raw_value(const Flow *f, int i) { return f->value[i][0] ? f->value[i] : f->fields[i].def; }

static int field_index(const Flow *f, const char *key)
{
    for (int i = 0; i < 2; i++)
        if (f->fields[i].key && !strcmp(f->fields[i].key, key)) return i;
    die("internal: %s has no field %s", f->id, key);
}

/* Parse one field: NULL, else "Label: reason" (Flow.validate). */
static const char *check_field(const Field *fd, const char *text, U256 *amount, Addr *addr)
{
    static char why[160];
    U256 u;
    Addr a;
    const char *e = fd->kind == FIELD_AMOUNT ? parse_units(text, fd->decimals, amount ? amount : &u)
                                             : parse_addr(text, addr ? addr : &a);
    if (!e) return NULL;
    snprintf(why, sizeof why, "%s: %s", fd->label, e);
    return why;
}

static const char *amount(const Flow *f, const char *key, U256 *out)
{
    int i = field_index(f, key);
    return check_field(&f->fields[i], raw_value(f, i), out, NULL);
}

static const char *address(const Flow *f, const char *key, Addr *out)
{
    int i = field_index(f, key);
    return check_field(&f->fields[i], raw_value(f, i), NULL, out);
}

/* NULL when every field parses, else the first problem. */
static const char *validate(const Flow *f)
{
    for (int i = 0; i < 2 && f->fields[i].key; i++) {
        const char *e = check_field(&f->fields[i], raw_value(f, i), NULL, NULL);
        if (e) return e;
    }
    return NULL;
}

#define TRY(x)                      \
    do {                            \
        const char *why_ = (x);     \
        if (why_) return why_;      \
    } while (0)

static void request(Request *r, int ins, ReqKind kind)
{
    r->ins = ins;
    r->kind = kind;
    r->payload.n = 0;
}

static const char *b_safe_usdc(const Flow *f, const Ctx *c, Request *r)
{
    U256 amt;
    Addr to;
    Buf raw = { 0 }, proof = { 0 };
    uint8_t canonical[SAFE_LEN];
    TRY(amount(f, "amount", &amt));
    TRY(address(f, "to", &to));
    TRY(erc20_proof(CHAIN_BASE, A(USDC_BASE), &proof));
    erc20_call(&raw, TRANSFER, to, &amt);
    safe_canonical(canonical, CHAIN_BASE, c->safe, A(USDC_BASE), &ZERO, &raw, SAFE_NONCE_BASE + c->take, 0, 0);
    request(r, INS_SIGN_USEROP, REQ_USEROP);
    safe_approve_hash(&r->payload, c, CHAIN_BASE, c->safe, canonical, &raw, &proof, NULL);
    return NULL;
}

static const char *b_safe_cow(const Flow *f, const Ctx *c, Request *r)
{
    U256 sell, buy;
    Buf data = { 0 }, cow = { 0 };
    uint8_t order[COW_LEN], canonical[SAFE_LEN];
    TRY(amount(f, "sell", &sell));
    TRY(amount(f, "buy", &buy));
    cow_order(order, CHAIN_BASE, A(WETH_BASE), A(USDC_BASE), &sell, &buy, 1000000000000000ULL, c->valid_to);
    presign(&data, order, c->safe);
    TRY(cow_trailer(&cow, order));
    safe_canonical(canonical, CHAIN_BASE, c->safe, A(GPV2_SETTLEMENT), &ZERO, &data, SAFE_NONCE_BASE + c->take, 0, 0);
    request(r, INS_SIGN_USEROP, REQ_USEROP);
    safe_approve_hash(&r->payload, c, CHAIN_BASE, c->safe, canonical, &data, NULL, &cow);
    return NULL;
}

static const char *b_safe_msend(const Flow *f, const Ctx *c, Request *r)
{
    U256 sell, buy;
    Buf approve = { 0 }, pre = { 0 }, packed = { 0 }, data = { 0 }, proof = { 0 }, cow = { 0 };
    uint8_t order[COW_LEN], canonical[SAFE_LEN];
    TRY(amount(f, "sell", &sell));
    TRY(amount(f, "buy", &buy));
    cow_order(order, CHAIN_BASE, A(USDC_BASE), A(DAI_BASE), &sell, &buy, 0, c->valid_to);
    erc20_call(&approve, APPROVE, A(VAULT_RELAYER), &sell);
    presign(&pre, order, c->safe);
    ms_record(&packed, A(USDC_BASE), &approve);
    ms_record(&packed, A(GPV2_SETTLEMENT), &pre);
    multisend(&data, &packed);
    TRY(erc20_proof(CHAIN_BASE, A(USDC_BASE), &proof));
    TRY(cow_trailer(&cow, order));
    safe_canonical(canonical, CHAIN_BASE, c->safe, A(MULTISEND_CALL_ONLY_V150), &ZERO, &data,
                   SAFE_NONCE_BASE + c->take, 1, 0);
    request(r, INS_SIGN_USEROP, REQ_USEROP);
    safe_approve_hash(&r->payload, c, CHAIN_BASE, c->safe, canonical, &data, &proof, &cow);
    return NULL;
}

static const char *b_usdc(const Flow *f, const Ctx *c, Request *r)
{
    U256 amt;
    Addr to;
    Buf data = { 0 }, proof = { 0 };
    TRY(amount(f, "amount", &amt));
    TRY(address(f, "to", &to));
    TRY(erc20_proof(CHAIN_BASE, A(USDC_BASE), &proof));
    erc20_call(&data, TRANSFER, to, &amt);
    request(r, INS_SIGN_USEROP, REQ_USEROP);
    userop_head(&r->payload, c->sender, CHAIN_BASE, c->flags, c->take, A(USDC_BASE), &ZERO, &data);
    trailers(&r->payload, &proof, NULL, NULL);
    return NULL;
}

static const char *b_send_eth(const Flow *f, const Ctx *c, Request *r)
{
    U256 amt;
    Addr to;
    Buf none = { 0 };
    TRY(amount(f, "amount", &amt));
    TRY(address(f, "to", &to));
    request(r, INS_SIGN_USEROP, REQ_USEROP);
    userop_head(&r->payload, c->sender, CHAIN_BASE, c->flags, c->take, to, &amt, &none);
    trailers(&r->payload, NULL, NULL, NULL);
    return NULL;
}

static const char *b_cow(const Flow *f, const Ctx *c, Request *r)
{
    U256 sell, buy;
    Buf data = { 0 }, cow = { 0 };
    uint8_t order[COW_LEN];
    TRY(amount(f, "sell", &sell));
    TRY(amount(f, "buy", &buy));
    cow_order(order, CHAIN_MAINNET, A(WETH_MAINNET), A(USDC_MAINNET), &sell, &buy, 1000000000000000ULL, c->valid_to);
    presign(&data, order, c->sender);
    TRY(cow_trailer(&cow, order));
    request(r, INS_SIGN_USEROP, REQ_USEROP);
    userop_head(&r->payload, c->sender, CHAIN_MAINNET, c->flags, c->take, A(GPV2_SETTLEMENT), &ZERO, &data);
    trailers(&r->payload, NULL, &cow, NULL);
    return NULL;
}

static const char *b_bybit(const Flow *f, const Ctx *c, Request *r)
{
    Buf raw = { 0 };
    uint8_t canonical[SAFE_LEN];
    (void)f;
    erc20_call(&raw, TRANSFER, A(BYBIT_SWEEPER), &ZERO);
    safe_canonical(canonical, CHAIN_MAINNET, A(BYBIT_SAFE), A(BYBIT_ATTACKER), &ZERO, &raw, 71, 1, 45746);
    request(r, INS_SIGN_USEROP, REQ_USEROP);
    safe_approve_hash(&r->payload, c, CHAIN_MAINNET, A(BYBIT_SAFE), canonical, &raw, NULL, NULL);
    return NULL;
}

static const char *b_address(const Flow *f, const Ctx *c, Request *r)
{
    (void)f;
    (void)c;
    request(r, INS_GET_WALLET_ADDRESS, REQ_ADDRESS);
    put_be(&r->payload, 0, 4); /* account 0 */
    put_u8(&r->payload, 1);    /* show it on the device */
    return NULL;
}

static const char *b_lock(const Flow *f, const Ctx *c, Request *r)
{
    (void)f;
    (void)c;
    request(r, INS_LOCK, REQ_LOCK);
    return NULL;
}

static Flow FLOWS[] = {
    {
        .key = '1', .id = "safe_usdc", .group = "Safe{Wallet}", .title = "Safe · USDC payment",
        .blurb = "A Safe pays USDC. PQ1 re-hashes the SafeTx itself and decodes the transfer.",
        .chain = "Base", .expect = EXPECT_SIGN,
        .on_device = {
            "APPROVE SAFE TX? opening ask",
            "Network, Safe account, Safe nonce",
            "USD Coin (verified), full recipient address, exact amount",
            "Read to the last screen, then press both buttons",
        },
        .fields = {
            { "amount", "Amount", "1,850,000", FIELD_AMOUNT, 6, "USDC" },
            { "to", "Recipient", ALICE, FIELD_ADDRESS, 0, "" },
        },
        .build = b_safe_usdc,
    },
    {
        .key = '2', .id = "safe_cow", .group = "Safe{Wallet}", .title = "Safe · CoW swap",
        .blurb = "A Safe pre-signs a CoW Protocol order. PQ1 decodes the full order, owned by the Safe.",
        .chain = "Base", .expect = EXPECT_SIGN,
        .on_device = {
            "Safe banner, then the order headline",
            "SELL WETH for at least USDC, both tokens verified",
            "Receiver = the Safe, fee, expiry",
        },
        .fields = {
            { "sell", "Sell", "500", FIELD_AMOUNT, 18, "WETH" },
            { "buy", "Buy at least", "1,842,310", FIELD_AMOUNT, 6, "USDC" },
        },
        .build = b_safe_cow,
    },
    {
        .key = '3', .id = "safe_msend", .group = "Safe{Wallet}", .title = "Safe · CoW swap, Safe UI batch",
        .blurb = "What the Safe web app really sends: approve + presign in a MultiSend DELEGATECALL. "
                 "Each record is decoded.",
        .chain = "Base", .expect = EXPECT_SIGN,
        .on_device = {
            "MultiSendCallOnly v1.5.0, 2 records",
            "RECORD 1/2: approve USDC to the CoW VaultRelayer",
            "RECORD 2/2: SELL USDC for at least DAI (exact, wrapped)",
        },
        .fields = {
            { "sell", "Sell", "2,500,000", FIELD_AMOUNT, 6, "USDC" },
            { "buy", "Buy at least", "2,497,512.345678901234567890", FIELD_AMOUNT, 18, "DAI" },
        },
        .build = b_safe_msend,
    },
    {
        .key = '4', .id = "usdc", .group = "Smart wallet", .title = "Send USDC",
        .blurb = "ERC-20 transfer from the PQ1 smart wallet, with the token proven against the on-device DB.",
        .chain = "Base", .expect = EXPECT_SIGN,
        .on_device = { "TRANSFER, USD Coin (verified)", "Full recipient address and exact amount", "Network Base, max fee" },
        .fields = {
            { "amount", "Amount", "487,250", FIELD_AMOUNT, 6, "USDC" },
            { "to", "Recipient", BOB, FIELD_ADDRESS, 0, "" },
        },
        .build = b_usdc,
    },
    {
        .key = '5', .id = "send", .group = "Smart wallet", .title = "Send ETH",
        .blurb = "Plain value transfer.",
        .chain = "Base", .expect = EXPECT_SIGN,
        .on_device = { "SEND, amount in ETH", "Full recipient address", "Network Base, max fee" },
        .fields = {
            { "amount", "Amount", "150", FIELD_AMOUNT, 18, "ETH" },
            { "to", "Recipient", ALICE, FIELD_ADDRESS, 0, "" },
        },
        .build = b_send_eth,
    },
    {
        .key = '6', .id = "cow", .group = "Smart wallet", .title = "CoW swap",
        .blurb = "The smart wallet pre-signs a CoW order directly. Order decoded on-device, no hash to trust.",
        .chain = "Ethereum", .expect = EXPECT_SIGN,
        .on_device = { "CoW order headline", "SELL WETH for at least USDC, fee, expiry", "Receiver = your wallet" },
        .fields = {
            { "sell", "Sell", "250", FIELD_AMOUNT, 18, "WETH" },
            { "buy", "Buy at least", "921,155", FIELD_AMOUNT, 6, "USDC" },
        },
        .build = b_cow,
    },
    {
        .key = '7', .id = "bybit", .group = "Attack replay", .title = "Bybit hack, replayed",
        .blurb = "Feb 2025, ~$1.5B. Signers saw a routine transfer; their devices got a DELEGATECALL to "
                 "attacker code. PQ1 decodes it and refuses.",
        .chain = "Ethereum", .expect = EXPECT_REFUSE,
        .on_device = {
            "No confirm screen at all",
            "Refusal names the DELEGATECALL to a non-allowlisted contract",
            "No signature leaves the device",
        },
        .build = b_bybit,
    },
};

static Flow DEVICE[] = {
    {
        .key = 'a', .id = "address", .group = "Device", .title = "Show address on PQ1",
        .blurb = "Confirm the wallet address on the trusted screen.", .chain = "", .expect = EXPECT_CONFIRM,
        .on_device = { "Your wallet address, then confirm" }, .build = b_address,
    },
    {
        .key = 'l', .id = "lock", .group = "Device", .title = "Lock PQ1",
        .blurb = "Wipe the unlocked session; PIN entry needed again.", .chain = "", .expect = EXPECT_LOCK,
        .on_device = { "LOCKED padlock, then the PIN row" }, .build = b_lock,
    },
};

#define NFLOWS (sizeof FLOWS / sizeof FLOWS[0])
#define NDEVICE (sizeof DEVICE / sizeof DEVICE[0])

static Flow *flow_by_key(int k)
{
    if (k < 0 || k > 255) return NULL;
    k = tolower(k);
    for (size_t i = 0; i < NFLOWS; i++)
        if (FLOWS[i].key == k) return &FLOWS[i];
    for (size_t i = 0; i < NDEVICE; i++)
        if (DEVICE[i].key == k) return &DEVICE[i];
    return NULL;
}

/* ── USB HID: one 64-byte report each way, no report IDs (nonsecure/src/usb/hid.rs) ─────── */

#define REPORT 64

typedef enum { IO_OK, IO_TIMEOUT, IO_GONE, IO_CANCELLED, IO_PROTO } IoErr;
static char g_ioerr[240]; /* what the last IoErr was about */

static __attribute__((format(printf, 2, 3))) IoErr fail(IoErr e, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(g_ioerr, sizeof g_ioerr, fmt, ap);
    va_end(ap);
    return e;
}

/*
 * hid_open:  1 connected, 0 no PQ1 on the bus, -1 error (g_ioerr).
 * hid_write: one OUT report, bounded: IO_TIMEOUT when PQ1 doesn't take it (busy on a dialog).
 * hid_read:  1 got an IN report, 0 none within `timeout_ms`, -1 the link is gone.
 */
#ifdef __APPLE__
#include <dlfcn.h>

/* IOKit + CoreFoundation by dlopen, so the binary needs no SDK to build: hidapi's mac pattern. */
typedef long CFIndex;
typedef int32_t IOReturn;
typedef void (*ReportCallback)(void *ctx, IOReturn result, void *sender, int type, uint32_t id, uint8_t *report, CFIndex len);
typedef void (*RemovalCallback)(void *ctx, IOReturn result, void *sender);

#define kIOReturnNotPrivileged ((IOReturn)0xe00002c1)
#define kIOReturnExclusiveAccess ((IOReturn)0xe00002c5)
#define kIOReturnUnsupported ((IOReturn)0xe00002c7)
#define kIOReturnTimeout ((IOReturn)0xe00002d6)
#define kIOReturnNotPermitted ((IOReturn)0xe00002e2)
#define kIOHIDReportTypeOutput 1
#define kCFNumberSInt32Type 3
#define kCFStringEncodingUTF8 0x08000100u
#define kCFRunLoopRunFinished 1

static struct {
    void *(*ManagerCreate)(const void *, uint32_t);
    void (*ManagerSetDeviceMatching)(void *, const void *);
    const void *(*ManagerCopyDevices)(void *);
    IOReturn (*DeviceOpen)(void *, uint32_t);
    IOReturn (*DeviceClose)(void *, uint32_t);
    void (*DeviceScheduleWithRunLoop)(void *, void *, const void *);
    void (*DeviceRegisterInputReportCallback)(void *, uint8_t *, CFIndex, ReportCallback, void *);
    void (*DeviceRegisterRemovalCallback)(void *, RemovalCallback, void *);
    IOReturn (*DeviceSetReportWithCallback)(void *, int, CFIndex, const uint8_t *, CFIndex, double, ReportCallback, void *);
    IOReturn (*DeviceSetReport)(void *, int, CFIndex, const uint8_t *, CFIndex);
    void *(*DictionaryCreateMutable)(const void *, CFIndex, const void *, const void *);
    void (*DictionarySetValue)(void *, const void *, const void *);
    const void *(*NumberCreate)(const void *, CFIndex, const void *);
    const void *(*StringCreateWithCString)(const void *, const char *, uint32_t);
    CFIndex (*SetGetCount)(const void *);
    void (*SetGetValues)(const void *, const void **);
    const void *(*Retain)(const void *);
    void (*Release)(const void *);
    void *(*RunLoopGetCurrent)(void);
    int32_t (*RunLoopRunInMode)(const void *, double, unsigned char);
    const void *const *RunLoopDefaultMode; /* &kCFRunLoopDefaultMode */
    const void *KeyCallBacks, *ValueCallBacks;
} K;

static bool iokit_load(void)
{
    static int state; /* 0 untried, 1 loaded, -1 failed */
    if (state) return state > 0;
    state = -1;
    void *io = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_NOW);
    void *cf = dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", RTLD_NOW);
    if (!io || !cf) {
        fail(IO_GONE, "cannot load IOKit: %s", dlerror());
        return false;
    }
#define SYM(lib, field, name)                                       \
    if (!(*(void **)&K.field = dlsym(lib, name))) {                 \
        fail(IO_GONE, "this macOS has no %s", name);                \
        return false;                                               \
    }
    SYM(io, ManagerCreate, "IOHIDManagerCreate");
    SYM(io, ManagerSetDeviceMatching, "IOHIDManagerSetDeviceMatching");
    SYM(io, ManagerCopyDevices, "IOHIDManagerCopyDevices");
    SYM(io, DeviceOpen, "IOHIDDeviceOpen");
    SYM(io, DeviceClose, "IOHIDDeviceClose");
    SYM(io, DeviceScheduleWithRunLoop, "IOHIDDeviceScheduleWithRunLoop");
    SYM(io, DeviceRegisterInputReportCallback, "IOHIDDeviceRegisterInputReportCallback");
    SYM(io, DeviceRegisterRemovalCallback, "IOHIDDeviceRegisterRemovalCallback");
    SYM(io, DeviceSetReportWithCallback, "IOHIDDeviceSetReportWithCallback");
    SYM(io, DeviceSetReport, "IOHIDDeviceSetReport");
    SYM(cf, DictionaryCreateMutable, "CFDictionaryCreateMutable");
    SYM(cf, DictionarySetValue, "CFDictionarySetValue");
    SYM(cf, NumberCreate, "CFNumberCreate");
    SYM(cf, StringCreateWithCString, "CFStringCreateWithCString");
    SYM(cf, SetGetCount, "CFSetGetCount");
    SYM(cf, SetGetValues, "CFSetGetValues");
    SYM(cf, Retain, "CFRetain");
    SYM(cf, Release, "CFRelease");
    SYM(cf, RunLoopGetCurrent, "CFRunLoopGetCurrent");
    SYM(cf, RunLoopRunInMode, "CFRunLoopRunInMode");
    SYM(cf, RunLoopDefaultMode, "kCFRunLoopDefaultMode");
    SYM(cf, KeyCallBacks, "kCFTypeDictionaryKeyCallBacks");
    SYM(cf, ValueCallBacks, "kCFTypeDictionaryValueCallBacks");
#undef SYM
    state = 1;
    return true;
}

#define FIFO 128
#define OUTS 64 /* write buffers: one IOKit may still hold after a timeout is not reused soon */
static void *g_manager, *g_matching, *g_dev;
static uint8_t g_in[REPORT], g_fifo[FIFO][REPORT], g_out[OUTS][REPORT];
static int g_head, g_count;
static bool g_removed, g_written;
static IOReturn g_write_result;
static uintptr_t g_write_seq;

static void on_report(void *ctx, IOReturn result, void *sender, int type, uint32_t id, uint8_t *report, CFIndex len)
{
    (void)ctx;
    (void)sender;
    (void)type;
    (void)id;
    if (result != 0 || len <= 0) return;
    if (g_count == FIFO) { /* drop the oldest */
        g_head = (g_head + 1) % FIFO;
        g_count--;
    }
    uint8_t *slot = g_fifo[(g_head + g_count++) % FIFO];
    memset(slot, 0, REPORT);
    memcpy(slot, report, len < REPORT ? (size_t)len : REPORT);
}

static void on_removed(void *ctx, IOReturn result, void *sender)
{
    (void)ctx;
    (void)result;
    (void)sender;
    g_removed = true;
}

static void on_written(void *ctx, IOReturn result, void *sender, int type, uint32_t id, uint8_t *report, CFIndex len)
{
    (void)sender;
    (void)type;
    (void)id;
    (void)report;
    (void)len;
    if ((uintptr_t)ctx != g_write_seq) return; /* a write we already gave up on */
    g_written = true;
    g_write_result = result;
}

static void pump(double seconds)
{
    if (K.RunLoopRunInMode(*K.RunLoopDefaultMode, seconds, 1) == kCFRunLoopRunFinished)
        usleep((useconds_t)(seconds * 1e6)); /* nothing scheduled: don't spin */
}

static bool hid_connected(void) { return g_dev != NULL; }

/* As hidapi does: drop the callbacks unless the device is gone, but always close (macOS 10.15+
 * can crash when a removed device is released without it). It stays scheduled on this, the
 * main, run loop until the release. */
static void hid_close(void)
{
    if (!g_dev) return;
    if (!g_removed) {
        K.DeviceRegisterInputReportCallback(g_dev, g_in, REPORT, NULL, NULL);
        K.DeviceRegisterRemovalCallback(g_dev, NULL, NULL);
    }
    K.DeviceClose(g_dev, 0);
    K.Release(g_dev);
    g_dev = NULL;
    g_count = 0;
}

static int hid_open(void)
{
    if (g_dev) return 1;
    if (!iokit_load()) return -1;
    if (!g_manager) {
        int vid = PQ1_VID, pid = PQ1_PID;
        const void *kv = K.StringCreateWithCString(NULL, "VendorID", kCFStringEncodingUTF8);
        const void *kp = K.StringCreateWithCString(NULL, "ProductID", kCFStringEncodingUTF8);
        const void *nv = K.NumberCreate(NULL, kCFNumberSInt32Type, &vid);
        const void *np = K.NumberCreate(NULL, kCFNumberSInt32Type, &pid);
        g_matching = K.DictionaryCreateMutable(NULL, 0, K.KeyCallBacks, K.ValueCallBacks);
        g_manager = K.ManagerCreate(NULL, 0);
        if (!kv || !kp || !nv || !np || !g_matching || !g_manager) {
            fail(IO_GONE, "cannot set up IOKit HID matching");
            return -1;
        }
        K.DictionarySetValue(g_matching, kv, nv);
        K.DictionarySetValue(g_matching, kp, np);
    }
    /* Re-matching re-enumerates, so a PQ1 that appeared after its PIN unlock is found. */
    K.ManagerSetDeviceMatching(g_manager, g_matching);
    const void *set = K.ManagerCopyDevices(g_manager);
    CFIndex n = set ? K.SetGetCount(set) : 0;
    if (n <= 0) {
        if (set) K.Release(set);
        return 0;
    }
    const void **devs = calloc((size_t)n, sizeof *devs);
    if (!devs) die("out of memory");
    K.SetGetValues(set, devs);
    void *dev = (void *)K.Retain(devs[0]);
    free(devs);
    K.Release(set);
    IOReturn r = K.DeviceOpen(dev, 0);
    if (r != 0) {
        K.Release(dev);
        if (r == kIOReturnNotPermitted || r == kIOReturnNotPrivileged)
            fail(IO_GONE, "macOS denied access to PQ1. Allow Terminal under System Settings > "
                          "Privacy & Security > Input Monitoring, then reopen it.");
        else if (r == kIOReturnExclusiveAccess)
            fail(IO_GONE, "another app is using PQ1 (a browser tab, or PQ1 Vault). Close it.");
        else
            fail(IO_GONE, "cannot open PQ1 (IOReturn 0x%08x)", (unsigned)r);
        return -1;
    }
    g_dev = dev;
    g_removed = false;
    g_count = 0;
    K.DeviceRegisterInputReportCallback(dev, g_in, REPORT, on_report, NULL);
    K.DeviceRegisterRemovalCallback(dev, on_removed, NULL);
    K.DeviceScheduleWithRunLoop(dev, K.RunLoopGetCurrent(), *K.RunLoopDefaultMode);
    return 1;
}

static IoErr hid_write(const uint8_t frame[REPORT])
{
    if (!g_dev || g_removed) {
        hid_close();
        return fail(IO_GONE, "PQ1 disconnected");
    }
    uint8_t *out = g_out[++g_write_seq % OUTS];
    memcpy(out, frame, REPORT);
    g_written = false;
    /* Bounded: while PQ1 shows a dialog it reads nothing, and the plain IOHIDDeviceSetReport
     * would wait for it forever. */
    IOReturn r = K.DeviceSetReportWithCallback(g_dev, kIOHIDReportTypeOutput, 0, out, REPORT, 2.0, on_written,
                                               (void *)g_write_seq);
    if (r == kIOReturnUnsupported) {
        g_write_result = K.DeviceSetReport(g_dev, kIOHIDReportTypeOutput, 0, out, REPORT);
        g_written = true;
    } else if (r != 0) {
        g_write_result = r;
        g_written = true;
    }
    for (long deadline = now_ms() + 2500; !g_written && !g_removed && now_ms() < deadline;) pump(0.05);
    if (g_removed) {
        hid_close();
        return fail(IO_GONE, "PQ1 disconnected");
    }
    if (!g_written || g_write_result == kIOReturnTimeout) return fail(IO_TIMEOUT, "PQ1 is not taking requests");
    if (g_write_result != 0) {
        IOReturn e = g_write_result;
        hid_close();
        return fail(IO_GONE, "USB write failed (IOReturn 0x%08x)", (unsigned)e);
    }
    return IO_OK;
}

static int hid_read(uint8_t frame[REPORT], int timeout_ms)
{
    for (long deadline = now_ms() + timeout_ms;;) {
        if (g_count) {
            memcpy(frame, g_fifo[g_head], REPORT);
            g_head = (g_head + 1) % FIFO;
            g_count--;
            return 1;
        }
        if (!g_dev || g_removed) {
            hid_close();
            fail(IO_GONE, "PQ1 disconnected");
            return -1;
        }
        long left = deadline - now_ms();
        if (left <= 0) return 0;
        pump((left < 100 ? left : 100) / 1000.0);
    }
}

#elif defined(__linux__)
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <strings.h>

/* /dev/hidrawN, for testing on a Linux bench (udev rule: 70-pq1-wallet.rules). */
static int g_fd = -1;

static bool hid_connected(void) { return g_fd >= 0; }

static void hid_close(void)
{
    if (g_fd >= 0) close(g_fd);
    g_fd = -1;
}

static int hid_open(void)
{
    if (g_fd >= 0) return 1;
    DIR *d = opendir("/sys/class/hidraw");
    if (!d) return 0;
    int r = 0;
    for (struct dirent *e; r <= 0 && (e = readdir(d));) {
        char path[512], line[256];
        bool match = false;
        if (strncmp(e->d_name, "hidraw", 6)) continue;
        snprintf(path, sizeof path, "/sys/class/hidraw/%s/device/uevent", e->d_name);
        FILE *f = fopen(path, "r");
        if (!f) continue;
        while (fgets(line, sizeof line, f))
            if (!strncasecmp(line, "HID_ID=0003:00001209:00007051", 29)) match = true;
        fclose(f);
        if (!match) continue;
        snprintf(path, sizeof path, "/dev/%s", e->d_name);
        g_fd = open(path, O_RDWR | O_CLOEXEC);
        r = g_fd >= 0 ? 1 : -1;
        if (r < 0) fail(IO_GONE, "cannot open %s: %s", path, strerror(errno));
    }
    closedir(d);
    return r;
}

static IoErr hid_write(const uint8_t frame[REPORT])
{
    uint8_t b[REPORT + 1] = { 0 }; /* leading 0: no report IDs */
    if (g_fd < 0) return fail(IO_GONE, "PQ1 disconnected");
    memcpy(b + 1, frame, REPORT);
    if (write(g_fd, b, sizeof b) == (ssize_t)sizeof b) return IO_OK;
    if (errno == ETIMEDOUT) return fail(IO_TIMEOUT, "PQ1 is not taking requests");
    int err = errno;
    hid_close();
    return fail(IO_GONE, "USB write failed (%s)", strerror(err));
}

static int hid_read(uint8_t frame[REPORT], int timeout_ms)
{
    struct pollfd p = { .fd = g_fd, .events = POLLIN };
    if (g_fd < 0) {
        fail(IO_GONE, "PQ1 disconnected");
        return -1;
    }
    int r = poll(&p, 1, timeout_ms);
    if (r == 0 || (r < 0 && errno == EINTR)) return 0;
    ssize_t n = r > 0 && (p.revents & POLLIN) ? read(g_fd, frame, REPORT) : -1;
    if (n <= 0) {
        hid_close();
        fail(IO_GONE, "PQ1 disconnected");
        return -1;
    }
    if (n < REPORT) memset(frame + n, 0, REPORT - (size_t)n);
    return 1;
}

#else
#error "PQ1 Demo supports macOS (and Linux for testing)"
#endif

/* ── APDU v2 over the HID frames (core/Apdu.kt, core/Pq1.kt; docs/companion/usb-protocol-v2.md):
 *    64-byte frames on channel 0x0001, tag 0x05, request chaining with P1=0x80, chunked replies
 *    drained with GET_RESPONSE. ── */

enum { CLA = 0xF0, TAG_PING = 0x02, TAG_APDU = 0x05, CHANNEL = 0x0001, P1_MORE = 0x80, P1_LAST = 0x00, INS_GET_RESPONSE = 0xC0 };
#define FIRST_DATA (REPORT - 7)
#define CONT_DATA (REPORT - 5)
#define MAX_APDU 4096 /* the firmware's framing limit */
#define CONFIRM_TIMEOUT_MS 300000L

typedef struct {
    int sw;
    size_t n;
    uint8_t d[CAP];
} Reply;

/* Called at least every 250 ms while waiting for a reply; true cancels the wait. */
static bool (*g_wait_hook)(void);

static void frames(const uint8_t *apdu, size_t n, Buf *out)
{
    uint8_t f[REPORT] = { CHANNEL >> 8, CHANNEL & 0xFF, TAG_APDU, 0, 0, (uint8_t)(n >> 8), (uint8_t)n };
    size_t k = n < FIRST_DATA ? n : FIRST_DATA;
    memcpy(f + 7, apdu, k);
    put(out, f, REPORT);
    for (size_t off = k, seq = 1; off < n; off += k, seq++) {
        memset(f, 0, REPORT);
        f[0] = CHANNEL >> 8;
        f[1] = CHANNEL & 0xFF;
        f[2] = TAG_APDU;
        f[3] = (uint8_t)(seq >> 8);
        f[4] = (uint8_t)seq;
        k = n - off < CONT_DATA ? n - off : CONT_DATA;
        memcpy(f + 5, apdu + off, k);
        put(out, f, REPORT);
    }
}

static IoErr write_apdu(const uint8_t *apdu, size_t n)
{
    static Buf fr;
    fr.n = 0;
    frames(apdu, n, &fr);
    for (size_t i = 0; i < fr.n; i += REPORT) {
        IoErr e = hid_write(fr.b + i);
        if (e) return e;
    }
    return IO_OK;
}

/* Discard stale IN reports (e.g. a reply to a request an earlier session abandoned). */
static void flush(void)
{
    uint8_t f[REPORT];
    while (hid_read(f, 20) == 1) {
    }
}

/* A barrier before each poll: PING with a fresh nonce and drop everything up to its echo. PQ1
 * echoes a tag-0x02 frame as-is, outside the APDU state (shared/src/apdu_framing.rs), and answers
 * in order, so a late reply to an earlier request, or to a write the OS kept queued after it
 * timed out, arrives before the echo and is never taken for the next answer. */
static IoErr sync_link(long timeout_ms)
{
    static uint64_t nonce;
    uint8_t f[REPORT] = { CHANNEL >> 8, CHANNEL & 0xFF, TAG_PING }, in[REPORT];
    if (!nonce) nonce = ((uint64_t)getpid() << 40) ^ ((uint64_t)time(NULL) << 8);
    set_be(f + 3, ++nonce, 8);
    IoErr e = hid_write(f);
    if (e) return e;
    for (long deadline = now_ms() + timeout_ms;;) {
        long left = deadline - now_ms();
        if (left <= 0) return fail(IO_TIMEOUT, "PQ1 is not answering");
        int k = hid_read(in, left < 250 ? (int)left : 250);
        if (k < 0) return IO_GONE;
        if (k == 1 && in[2] == TAG_PING && !memcmp(in + 3, f + 3, 8)) return IO_OK;
    }
}

static IoErr read_reply(Reply *r, long timeout_ms)
{
    static uint8_t acc[MAX_APDU + REPORT];
    uint8_t f[REPORT];
    size_t got = 0, expected = 0;
    unsigned seq = 0;
    long deadline = now_ms() + timeout_ms;
    for (;;) {
        if (g_wait_hook && g_wait_hook()) return fail(IO_CANCELLED, "cancelled");
        long left = deadline - now_ms();
        if (left <= 0) return fail(IO_TIMEOUT, "no reply within %lds", timeout_ms / 1000);
        int k = hid_read(f, left < 250 ? (int)left : 250);
        if (k < 0) return IO_GONE;
        if (k == 0 || f[2] != TAG_APDU) continue;
        unsigned rseq = (unsigned)f[3] << 8 | f[4];
        if (seq == 0 && rseq != 0) continue; /* the tail of a stale reply */
        if (rseq != seq) return fail(IO_PROTO, "HID seq mismatch: want %u, got %u", seq, rseq);
        size_t off, chunk;
        if (seq == 0) {
            expected = (size_t)f[5] << 8 | f[6];
            if (expected > MAX_APDU) return fail(IO_PROTO, "reply too long (%zu B)", expected);
            off = 7;
            chunk = expected < FIRST_DATA ? expected : FIRST_DATA;
        } else {
            off = 5;
            chunk = expected - got < CONT_DATA ? expected - got : CONT_DATA;
        }
        memcpy(acc + got, f + off, chunk);
        got += chunk;
        seq++;
        if (got >= expected) break;
    }
    if (expected < 2) return fail(IO_PROTO, "reply too short (%zu B)", expected);
    r->sw = acc[expected - 2] << 8 | acc[expected - 1];
    r->n = expected - 2;
    memcpy(r->d, acc, r->n);
    return IO_OK;
}

static IoErr exchange(const uint8_t *apdu, size_t n, long timeout_ms, Reply *r)
{
    IoErr e = write_apdu(apdu, n);
    return e ? e : read_reply(r, timeout_ms);
}

/* `r` holds the first reply; while SW is 61xx, fetch the rest with GET_RESPONSE. */
static IoErr drain(Reply *r)
{
    static const uint8_t get_response[] = { CLA, INS_GET_RESPONSE, 0, 0, 0 };
    static Reply next;
    for (int rounds = 0; r->sw >> 8 == 0x61;) {
        if (++rounds > 200) return fail(IO_PROTO, "GET_RESPONSE drain exceeded 200 rounds");
        IoErr e = exchange(get_response, sizeof get_response, 5000, &next);
        if (e) return e;
        if (next.n > CAP - r->n) return fail(IO_PROTO, "reply over %d B", CAP);
        memcpy(r->d + r->n, next.d, next.n);
        r->n += next.n;
        r->sw = next.sw;
    }
    return IO_OK;
}

/* A single APDU (payload ≤ 255 B), reply drained. */
static IoErr send_apdu(int ins, const uint8_t *data, size_t n, long timeout_ms, Reply *r)
{
    uint8_t apdu[5 + 255] = { CLA, (uint8_t)ins, P1_LAST, 0, (uint8_t)n };
    if (n > 255) die("internal: APDU payload %zu B", n);
    if (n) memcpy(apdu + 5, data, n);
    IoErr e = exchange(apdu, 5 + n, timeout_ms, r);
    return e ? e : drain(r);
}

/* Chained send; the last block's reply may take up to `last_timeout_ms` (the user reading the
 * device screens). `on_last_sent` fires once every block is on the wire. */
static IoErr send_chained(int ins, const Buf *p, long last_timeout_ms, void (*on_last_sent)(void), Reply *r)
{
    for (size_t off = 0;;) {
        size_t n = p->n - off < 255 ? p->n - off : 255;
        bool last = off + n == p->n;
        uint8_t apdu[5 + 255] = { CLA, (uint8_t)ins, last ? P1_LAST : P1_MORE, 0, (uint8_t)n };
        IoErr e;
        memcpy(apdu + 5, p->b + off, n);
        if (last) {
            if ((e = write_apdu(apdu, 5 + n))) return e;
            on_last_sent();
            e = read_reply(r, last_timeout_ms);
            return e ? e : drain(r);
        }
        if ((e = exchange(apdu, 5 + n, 5000, r)) || (e = drain(r))) return e;
        if (r->sw != SW_OK) return IO_OK;
        off += n;
    }
}

/* What came back from one request. */
typedef enum {
    O_SIGNED,
    O_DECLINED,
    O_REFUSED,
    O_IDLE_WIPED,
    O_NOT_READY,
    O_CONFIRMED,
    O_LOCKED,
    O_ABANDONED,
    O_FAILED,
} OutcomeKind;

typedef struct {
    OutcomeKind kind;
    int sw;                 /* O_REFUSED */
    size_t sig_len;         /* O_SIGNED */
    uint8_t sig_sha256[32]; /* O_SIGNED */
    Addr address;           /* O_CONFIRMED */
    char msg[240];          /* O_FAILED */
} Outcome;

typedef struct {
    bool unlocked;
    int attempts; /* PIN attempts left, -1 unknown */
} Status;

static IoErr pq1_status(Status *s)
{
    static Reply r;
    IoErr e = send_apdu(INS_GET_STATUS, NULL, 0, 1500, &r);
    if (e) return e;
    /* commands.rs: byte 0 is 0 when UNLOCKED, 1 when locked; byte 1 the PIN attempts left. */
    s->unlocked = r.sw == SW_OK && r.n > 0 && r.d[0] == 0;
    s->attempts = r.sw == SW_OK && r.n > 1 ? r.d[1] : -1;
    return IO_OK;
}

/* The first call after unlock runs the master keygen (seconds on silicon). */
static IoErr pq1_wallet(Addr *a)
{
    static Reply r;
    static const uint8_t account0[4];
    IoErr e = send_apdu(INS_GET_WALLET_ADDRESS, account0, sizeof account0, 20000, &r);
    if (e) return e;
    if (r.sw != SW_OK || r.n != 20) return fail(IO_PROTO, "GET_WALLET_ADDRESS failed (SW=%04X)", r.sw);
    memcpy(a->b, r.d, 20);
    return IO_OK;
}

static void failed(Outcome *o, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void failed(Outcome *o, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    o->kind = O_FAILED;
    vsnprintf(o->msg, sizeof o->msg, fmt, ap);
    va_end(ap);
}

/* [count 8][init len 4][init][t1 len 4][t1][t2 len 4][t2 = abi.encode(ownerIndex, bytes sig)]. */
static void parse_userop(const Reply *r, Outcome *o)
{
    const uint8_t *d = r->d;
    size_t n = r->n, off = 8, len[3];
    for (int i = 0; i < 3; i++) {
        if (n < off + 4) goto truncated;
        len[i] = (size_t)be(d + off, 4);
        off += 4;
        if (len[i] > n - off) goto truncated;
        if (i < 2) off += len[i];
    }
    if (len[2] < 96) goto truncated;
    uint64_t sig_len = be(d + off + 64, 32);
    if (off + len[2] != n || len[2] != SIG_WRAPPER_LEN || sig_len != C10_SIG_LEN) {
        failed(o, "Signed, but the reply is malformed (%zu B)", n);
        return;
    }
    o->kind = O_SIGNED;
    o->sig_len = (size_t)sig_len;
    sha256(d + off + 96, o->sig_len, o->sig_sha256);
    return;
truncated:
    failed(o, "Signed, but the reply is truncated (%zu B)", n);
}

static void interpret(const Request *q, const Reply *r, Outcome *o)
{
    switch (r->sw) {
    case SW_OK: break;
    case SW_DECLINED: o->kind = O_DECLINED; return;
    case SW_IDLE_WIPED: o->kind = O_IDLE_WIPED; return;
    case SW_NOT_READY: o->kind = O_NOT_READY; return;
    default:
        o->kind = O_REFUSED;
        o->sw = r->sw;
        return;
    }
    switch (q->kind) {
    case REQ_LOCK: o->kind = O_LOCKED; break;
    case REQ_ADDRESS:
        if (r->n != 20) {
            failed(o, "address reply %zu B", r->n);
            break;
        }
        o->kind = O_CONFIRMED;
        memcpy(o->address.b, r->d, 20);
        break;
    case REQ_USEROP: parse_userop(r, o); break;
    }
}

static void pq1_run(const Request *q, void (*on_waiting)(void), Outcome *o)
{
    static Reply r;
    IoErr e;
    flush();
    if (q->kind == REQ_USEROP) {
        e = send_chained(q->ins, &q->payload, CONFIRM_TIMEOUT_MS, on_waiting, &r);
    } else {
        on_waiting();
        e = send_apdu(q->ins, q->payload.b, q->payload.n, CONFIRM_TIMEOUT_MS, &r);
    }
    if (e == IO_OK) interpret(q, &r, o);
    else if (e == IO_CANCELLED) o->kind = O_ABANDONED;
    else if (e == IO_TIMEOUT) failed(o, "No answer from PQ1 (%s)", g_ioerr);
    else failed(o, "%s", g_ioerr);
}

/* ── terminal UI (DemoViewModel, DemoScreen, CardStatus) ───────────────────────────────── */

#define RESET "\x1b[0m"
#define BOLD "\x1b[1m"
#define DIM "\x1b[90m"
#define GREEN "\x1b[32m"
#define AMBER "\x1b[33m"
#define RED "\x1b[31m"

/* BUSY: on the bus but not answering, i.e. showing a PIN prompt or a dialog. */
typedef enum { CONN_NONE, CONN_BUSY, CONN_LOCKED, CONN_UNLOCKED, CONN_ERROR } Conn;
typedef enum { PHASE_PENDING, PHASE_SENDING, PHASE_WAITING, PHASE_DONE } Phase;

static struct {
    Conn conn;
    int attempts; /* PIN attempts left, -1 unknown */
    char conn_err[240];
    bool have_wallet, deriving;
    Addr wallet;
    uint64_t take; /* requests sent: the UserOp nonce; the Safe nonce is 17 + take */
    Addr safe;
    Flow *active;  /* the demo on stage */
    Flow *queued;  /* picked while another request was on the device; starts once that is answered */
    Phase phase;
    char note[120]; /* why a pending demo is (back) here */
    long since_ms, shown_secs;
    Outcome out;
    char msg[160];
    bool dirty, cancel;
} S;

static const char *state_path(void)
{
    static char p[1024];
    const char *home = getenv("HOME");
    snprintf(p, sizeof p, "%s/.pq1-demo", home && *home ? home : ".");
    return p;
}

static void load_state(void)
{
    char line[256];
    S.safe = A(DEMO_SAFE);
    FILE *f = fopen(state_path(), "r");
    if (!f) return;
    while (fgets(line, sizeof line, f)) {
        unsigned long long take;
        Addr safe;
        if (sscanf(line, "take=%llu", &take) == 1) S.take = take;
        else if (!strncmp(line, "safe=", 5) && !parse_addr(line + 5, &safe)) S.safe = safe;
    }
    fclose(f);
}

static void save_state(void)
{
    char h[41];
    FILE *f = fopen(state_path(), "w");
    if (!f) return;
    hex(h, S.safe.b, 20);
    fprintf(f, "take=%llu\nsafe=0x%s\n", (unsigned long long)S.take, h);
    fclose(f);
}

/* ── terminal ── */

static struct termios g_tty0;
static bool g_tty;

static void tty_raw(bool on)
{
    struct termios t = g_tty0;
    if (!g_tty) return;
    if (on) {
        t.c_lflag &= ~(tcflag_t)(ICANON | ECHO | ISIG | IEXTEN);
        t.c_iflag &= ~(tcflag_t)(IXON | ICRNL);
        t.c_cc[VMIN] = 1;
        t.c_cc[VTIME] = 0;
    }
    tcsetattr(0, TCSANOW, &t);
}

static void restore_tty(void)
{
    if (g_tty) tcsetattr(0, TCSANOW, &g_tty0);
    fputs(RESET "\x1b[?25h\n", stdout);
    fflush(stdout);
}

static void on_signal(int sig)
{
    static const char s[] = RESET "\x1b[?25h\n";
    if (g_tty) tcsetattr(0, TCSANOW, &g_tty0);
    if (write(1, s, sizeof s - 1) < 0) _exit(128 + sig);
    _exit(128 + sig);
}

static _Noreturn void quit(void)
{
    hid_close();
    printf("\x1b[H\x1b[2J");
    exit(0);
}

enum { KEY_NONE = -1, KEY_EOF = -2, KEY_CTRL_C = 3, KEY_ESC = 27 };

static bool stdin_ready(int timeout_ms)
{
    fd_set s;
    struct timeval tv = { .tv_sec = timeout_ms / 1000, .tv_usec = timeout_ms % 1000 * 1000 };
    FD_ZERO(&s);
    FD_SET(0, &s);
    return select(1, &s, NULL, NULL, timeout_ms < 0 ? NULL : &tv) > 0;
}

/* One key press, or KEY_NONE after `timeout_ms` (< 0 waits). Arrow keys and other escape
 * sequences are swallowed so they don't read as Esc. */
static int read_key(int timeout_ms)
{
    unsigned char c;
    bool seq = false;
    if (!stdin_ready(timeout_ms)) return KEY_NONE;
    if (read(0, &c, 1) != 1) return KEY_EOF;
    if (c != KEY_ESC) return c;
    while (stdin_ready(30) && read(0, &c, 1) == 1) seq = true;
    return seq ? KEY_NONE : KEY_ESC;
}

/* A line in cooked mode; false on end of input. */
static bool prompt_line(const char *prompt, char *out, size_t n)
{
    tty_raw(false);
    printf("\x1b[?25h%s", prompt);
    fflush(stdout);
    ssize_t k = read(0, out, n - 1);
    tty_raw(true);
    printf("\x1b[?25l");
    if (k <= 0) return false;
    out[k] = 0;
    out[strcspn(out, "\r\n")] = 0;
    return true;
}

static int term_cols(void)
{
    struct winsize w;
    return ioctl(1, TIOCGWINSZ, &w) == 0 && w.ws_col >= 60 ? w.ws_col : 80;
}

/* Ask Terminal for room to show the whole menu and the stage. */
static void fit_window(void)
{
    struct winsize w;
    if (ioctl(1, TIOCGWINSZ, &w) == 0 && (w.ws_row < 36 || w.ws_col < 100))
        printf("\x1b[8;%d;%dt", w.ws_row < 36 ? 36 : w.ws_row, w.ws_col < 100 ? 100 : w.ws_col);
}

/* ── text ── */

static int width(const char *s) /* terminal columns: one per UTF-8 code point */
{
    int w = 0;
    for (; *s; s++) w += ((unsigned char)*s & 0xC0) != 0x80;
    return w;
}

/* `s` in exactly `w` columns: padded, or cut with "…". */
static void cell(const char *s, int w)
{
    int n = width(s), k = 0;
    if (n <= w) {
        printf("%s%*s", s, w - n, "");
        return;
    }
    for (; *s; s++) {
        if (((unsigned char)*s & 0xC0) != 0x80 && ++k > w - 1) break;
        putchar(*s);
    }
    fputs("…", stdout);
}

/* Word-wrap `text` to `w` columns, every line indented by `indent`. */
static void wrap(const char *text, int indent, int w)
{
    int col = 0;
    for (const char *p = text; *p;) {
        char word[200];
        size_t n = strcspn(p, " ");
        if (!n) {
            p++;
            continue;
        }
        if (n >= sizeof word) n = sizeof word - 1;
        memcpy(word, p, n);
        word[n] = 0;
        p += n;
        int ww = width(word);
        if (col && col + 1 + ww > w) {
            putchar('\n');
            col = 0;
        }
        if (col) {
            printf(" %s", word);
            col += 1 + ww;
        } else {
            printf("%*s%s", indent, "", word);
            col = indent + ww;
        }
    }
    if (col) putchar('\n');
}

/* "0x 1234 5678 …": groups of four, easy to compare with the device screen. */
static void chunk(char *out, const uint8_t a[20])
{
    char h[41];
    hex(h, a, 20);
    out += sprintf(out, "0x");
    for (int i = 0; i < 40; i += 4) out += sprintf(out, " %.4s", h + i);
}

static void short_addr(char *out, size_t n, const char *s)
{
    char t[128];
    trim(t, sizeof t, s);
    size_t k = strlen(t);
    if (k <= 12) snprintf(out, n, "%.12s", t);
    else snprintf(out, n, "%.6s…%s", t, t + k - 4);
}

/* "1,850,000 USDC → 0xbD54…9abB": a flow's current values, for its menu line. */
static void summary(const Flow *f, char *out, size_t n)
{
    size_t k = 0;
    out[0] = 0;
    if (f->expect == EXPECT_REFUSE) {
        snprintf(out, n, "PQ1 should refuse");
        return;
    }
    for (int i = 0; i < 2 && f->fields[i].key && k < n; i++) {
        const Field *fd = &f->fields[i];
        char v[128], a[40];
        trim(v, sizeof v, raw_value(f, i));
        if (fd->kind == FIELD_ADDRESS) {
            short_addr(a, sizeof a, v);
            k += (size_t)snprintf(out + k, n - k, " → %s", a);
        } else if (!strcmp(fd->key, "sell")) {
            k += (size_t)snprintf(out + k, n - k, "sell %s %s", v, fd->suffix);
        } else if (!strcmp(fd->key, "buy")) {
            k += (size_t)snprintf(out + k, n - k, " for ≥ %s %s", v, fd->suffix);
        } else {
            k += (size_t)snprintf(out + k, n - k, "%s %s", v, fd->suffix);
        }
    }
}

static void commas(char *out, unsigned long long v) /* "%,d" */
{
    char t[32];
    int n = snprintf(t, sizeof t, "%llu", v);
    for (int i = 0; i < n; i++) {
        *out++ = t[i];
        if ((n - i - 1) % 3 == 0 && i < n - 1) *out++ = ',';
    }
    *out = 0;
}

/* ── screen ── */

typedef struct {
    const char *color, *mark;
    char title[64], body[240];
} Verdict;

static Verdict verdict_of(const char *color, const char *mark, const char *title, const char *body)
{
    Verdict v = { color, mark, "", "" };
    snprintf(v.title, sizeof v.title, "%s", title);
    snprintf(v.body, sizeof v.body, "%s", body);
    return v;
}

static Verdict verdict(Expect expect, const Outcome *o)
{
    char t[64], a[64];
    switch (o->kind) {
    case O_SIGNED:
        return expect == EXPECT_REFUSE
                   ? verdict_of(RED, "!", "PQ1 signed", "This should have been refused. Check the firmware build.")
                   : verdict_of(GREEN, "✓", "Signed", "SPHINCS+ C10 post-quantum signature, made and verified inside PQ1.");
    case O_REFUSED:
        if (expect == EXPECT_REFUSE)
            return verdict_of(GREEN, "✓", "Attack blocked",
                              "PQ1 saw a DELEGATECALL to unknown code and refused. No signature left the device.");
        snprintf(t, sizeof t, "PQ1 refused (SW %04X)", o->sw);
        return verdict_of(AMBER, "!", t, "A firmware gate refused it. The device screen says which.");
    case O_DECLINED: return verdict_of(DIM, "✕", "Declined on PQ1", "Nothing was signed.");
    case O_IDLE_WIPED: return verdict_of(AMBER, "!", "PQ1 locked itself", "The 120 s idle timer fired while waiting.");
    case O_NOT_READY: return verdict_of(AMBER, "!", "PQ1 not ready", "Locked or busy. Press the key to try again.");
    case O_CONFIRMED:
        chunk(a, o->address.b);
        return verdict_of(GREEN, "✓", "Address confirmed", a);
    case O_LOCKED: return verdict_of(GREEN, "✓", "PQ1 locked", "Secrets wiped. Enter the PIN to continue.");
    case O_ABANDONED: return verdict_of(DIM, "·", "Stopped waiting", "If PQ1 still shows it, decline there (hold left).");
    case O_FAILED: break;
    }
    return verdict_of(RED, "!", "Failed", o->msg);
}

static void line(const char *color, const char *text) { printf(" %s●" RESET " %s", color, text); }

static void wait_line(void)
{
    Expect e = S.active->expect;
    long secs = (now_ms() - S.since_ms) / 1000;
    S.shown_secs = secs < 0 ? 0 : secs;
    printf("\r\x1b[K");
    line(GREEN, e == EXPECT_REFUSE ? "Look at PQ1. It should refuse."
                : e == EXPECT_LOCK ? "Locking…"
                                   : "Look at PQ1. Both buttons sign, hold left declines.");
    printf("  " BOLD "%lds" RESET DIM "   Esc stops waiting" RESET, S.shown_secs);
}

static void header(void)
{
    char c[64];
    printf("\n " BOLD "PQ1" RESET DIM " demo" RESET "    ");
    switch (S.conn) {
    case CONN_NONE: printf(DIM "○ Not connected" RESET); break;
    case CONN_BUSY: printf(AMBER "● Not answering" RESET); break;
    case CONN_LOCKED: printf(AMBER "● Locked" RESET); break;
    case CONN_UNLOCKED:
        printf(GREEN "● Unlocked" RESET);
        if (S.attempts >= 0) printf(DIM "   PIN attempts left: %d" RESET, S.attempts);
        break;
    case CONN_ERROR: printf(RED "● USB problem" RESET); break;
    }
    printf("    " DIM "Nothing is broadcast." RESET "\n");
    if (S.conn == CONN_UNLOCKED && S.have_wallet) {
        chunk(c, S.wallet.b);
        printf(DIM " SMART WALLET  " RESET "%s" DIM "  same address on every chain" RESET "\n", c);
    } else if (S.conn == CONN_UNLOCKED && S.deriving) {
        printf(DIM " SMART WALLET  deriving the post-quantum keys on PQ1…" RESET "\n");
    } else {
        putchar('\n');
    }
}

static void group_label(const char *g)
{
    printf(" " DIM);
    for (; *g; g++) putchar(toupper((unsigned char)*g));
    printf(RESET "\n");
}

static void menu(void)
{
    const char *group = "";
    int room = term_cols() - 50;
    putchar('\n');
    for (size_t i = 0; i < NFLOWS; i++) {
        Flow *f = &FLOWS[i];
        char sum[300];
        if (strcmp(group, f->group)) group_label(group = f->group);
        summary(f, sum, sizeof sum);
        printf("   %s%c  ", f == S.queued ? AMBER : f == S.active ? BOLD : "", f->key);
        cell(f->title, 31);
        printf("  ");
        cell(f->chain, 9);
        printf("  ");
        cell(sum, room < 20 ? 20 : room);
        printf(RESET "\n");
    }
    group_label("Device");
    for (size_t i = 0; i < NDEVICE; i++) {
        Flow *f = &DEVICE[i];
        printf("   %s%c  ", f == S.queued ? AMBER : f == S.active ? BOLD : "", f->key);
        cell(f->title, 31);
        printf(RESET);
    }
    printf("\n\n " DIM "e edit amounts  ·  s Safe address  ·  r reset counter (%llu sent)  ·  q quit" RESET "\n",
           (unsigned long long)S.take);
}

static void stage(void)
{
    const Flow *f = S.active;
    printf(" " DIM);
    for (int i = term_cols() - 2; i > 0; i--) fputs("─", stdout);
    printf(RESET "\n");
    if (!f) {
        const char *big = "", *body = "";
        switch (S.conn) {
        case CONN_NONE:
            big = "Plug in PQ1";
            body = "USB-C. PQ1 appears over USB once it is unlocked with its PIN.";
            break;
        case CONN_BUSY:
            big = "PQ1 is busy";
            body = "Unlock it with the PIN, or answer what its screen shows.";
            break;
        case CONN_LOCKED:
            big = "Unlock PQ1";
            body = "Enter the PIN on the device. Idle for 120 s, it locks itself again.";
            break;
        case CONN_UNLOCKED:
            big = "Ready";
            body = "Press 1-7 to run a demo. PQ1 shows it on its own screen.";
            break;
        case CONN_ERROR:
            big = "USB problem";
            body = S.conn_err;
            break;
        }
        printf(" " BOLD "%s" RESET "\n" DIM, big);
        wrap(body, 1, term_cols() - 4);
        printf(RESET);
        if (S.msg[0]) printf("\n %s\n", S.msg);
        return;
    }
    printf(" " BOLD "%s" RESET, f->title);
    if (*f->chain) printf(DIM "  ·  %s" RESET, f->chain);
    if (f->expect == EXPECT_REFUSE) printf("   " RED "PQ1 should refuse" RESET);
    printf("\n" DIM);
    wrap(f->blurb, 1, term_cols() - 4);
    printf(RESET "\n " DIM "ON THE PQ1 SCREEN" RESET "\n");
    for (int i = 0; i < 4 && f->on_device[i]; i++) printf("   " GREEN "›" RESET " %s\n", f->on_device[i]);
    putchar('\n');
    if (S.queued) {
        char t[200];
        snprintf(t, sizeof t, "Next: %s. Decline the current request on PQ1 (hold left) to switch.", S.queued->title);
        line(AMBER, t);
        printf(DIM "   x cancels" RESET "\n");
    }
    switch (S.phase) {
    case PHASE_PENDING:
        if (S.note[0]) {
            line(AMBER, S.note);
            putchar('\n');
        }
        switch (S.conn) {
        case CONN_NONE: line(AMBER, "Plug in PQ1 and unlock it. Starts by itself."); break;
        case CONN_BUSY: line(AMBER, "PQ1 is busy: unlock it, or answer its screen. Starts by itself."); break;
        case CONN_LOCKED: line(AMBER, "Unlock PQ1 with the PIN. Starts by itself."); break;
        case CONN_UNLOCKED: line(AMBER, "Starting…"); break;
        case CONN_ERROR: line(AMBER, S.conn_err); break;
        }
        printf(DIM "   Esc cancels" RESET);
        break;
    case PHASE_SENDING: line(GREEN, "Sending to PQ1…"); break;
    case PHASE_WAITING: wait_line(); break;
    case PHASE_DONE: {
        Verdict v = verdict(f->expect, &S.out);
        printf(" %s" BOLD "%s %s" RESET "\n   %s\n", v.color, v.mark, v.title, v.body);
        if (S.out.kind == O_SIGNED) {
            char h[65], n[32];
            hex(h, S.out.sig_sha256, 32);
            commas(n, S.out.sig_len);
            printf(DIM "   %s B signature · sha256 %.12s…" RESET "\n", n, h);
        }
        printf(DIM "   Press %c to run it again, Esc to clear." RESET, f->key);
        break;
    }
    }
}

static void render(void)
{
    S.dirty = false;
    printf("\x1b[H\x1b[2J");
    header();
    menu();
    putchar('\n');
    stage();
    fflush(stdout);
}

/* ── the loop (DemoViewModel) ── */

static void set_conn(Conn c)
{
    if (S.conn != c) S.dirty = true;
    S.conn = c;
}

static void drop(void)
{
    hid_close();
    S.have_wallet = false;
    set_conn(CONN_NONE);
}

/* Connect, read the lock state, and fetch the wallet address once per connection. */
static void tick(void)
{
    Status st;
    if (!hid_connected()) {
        int r = hid_open();
        if (r == 0) {
            drop();
            return;
        }
        if (r < 0) {
            if (strcmp(S.conn_err, g_ioerr)) S.dirty = true;
            snprintf(S.conn_err, sizeof S.conn_err, "%s", g_ioerr);
            set_conn(CONN_ERROR);
            return;
        }
    }
    IoErr e = sync_link(1500);
    if (e == IO_OK) e = pq1_status(&st);
    if (e == IO_TIMEOUT) { /* enumerated but silent: relocked with the PIN prompt up, or a dialog */
        set_conn(CONN_BUSY);
        return;
    }
    if (e) {
        drop();
        return;
    }
    if (!st.unlocked) {
        set_conn(CONN_LOCKED);
        return;
    }
    if (S.attempts != st.attempts) S.dirty = true;
    S.attempts = st.attempts;
    set_conn(CONN_UNLOCKED);
    if (S.have_wallet) return;
    S.deriving = true;
    render();
    e = pq1_wallet(&S.wallet);
    S.deriving = false;
    S.dirty = true;
    if (e == IO_OK) S.have_wallet = true;
    else if (e == IO_TIMEOUT) set_conn(CONN_BUSY);
    else if (e == IO_GONE) drop();
}

/* Polled while a request is on the device: keys, queueing, and the seconds counter. */
static bool wait_hook(void)
{
    for (int k; (k = read_key(0)) != KEY_NONE;) {
        Flow *f = flow_by_key(k);
        if (k == KEY_CTRL_C || k == KEY_EOF) quit();
        if (k == KEY_ESC) {
            S.cancel = true;
        } else if (k == 'x' && S.queued) {
            S.queued = NULL;
            S.dirty = true;
        } else if (f && f != S.active && f != S.queued) {
            S.queued = f;
            S.dirty = true;
        }
    }
    if (S.dirty) {
        render();
    } else if (S.phase == PHASE_WAITING && (now_ms() - S.since_ms) / 1000 != S.shown_secs) {
        wait_line();
        fflush(stdout);
    }
    return S.cancel;
}

static void on_waiting(void)
{
    S.phase = PHASE_WAITING;
    S.since_ms = now_ms();
    render();
}

/* Build and send the active demo; afterwards start the queued one, or re-run after a relock. */
static void execute(Flow *f)
{
    static Request req;
    Outcome o = { 0 };
    Addr sender = S.wallet;
    S.cancel = false;
    S.phase = PHASE_SENDING;
    render();
    g_wait_hook = wait_hook;
    IoErr e = S.have_wallet ? IO_OK : pq1_wallet(&sender);
    if (e == IO_CANCELLED) {
        o.kind = O_ABANDONED;
    } else if (e) {
        failed(&o, "%s", g_ioerr);
    } else {
        Ctx c = { .sender = sender, .take = S.take, .valid_to = (uint64_t)time(NULL) + 3600, .safe = S.safe };
        const char *why = f->build(f, &c, &req);
        S.wallet = sender;
        S.have_wallet = true;
        if (why) {
            failed(&o, "%s", why);
        } else {
            if (req.kind == REQ_USEROP) {
                S.take++;
                save_state();
            }
            pq1_run(&req, on_waiting, &o);
        }
    }
    g_wait_hook = NULL;
    if (!hid_connected()) drop();
    if (o.kind == O_LOCKED || o.kind == O_IDLE_WIPED) set_conn(CONN_LOCKED);
    /* PQ1 relocked or was unplugged mid-request: wait for the next unlock and run it again. */
    const char *retry = o.kind == O_IDLE_WIPED                      ? "PQ1 locked itself while waiting (idle timeout)."
                        : o.kind == O_FAILED && !hid_connected() ? "PQ1 was disconnected."
                                                                   : NULL;
    Flow *next = S.queued;
    S.queued = NULL;
    S.note[0] = 0;
    S.dirty = true;
    if (o.kind != O_ABANDONED && next) {
        S.active = next;
        S.phase = PHASE_PENDING;
    } else if (o.kind != O_ABANDONED && retry) {
        S.phase = PHASE_PENDING;
        snprintf(S.note, sizeof S.note, "%s", retry);
    } else {
        S.phase = PHASE_DONE;
        S.out = o;
    }
}

static void edit_amounts(void)
{
    printf("\n\n " BOLD "Edit amounts." RESET " Which demo, 1-6? " DIM "(Esc cancels)" RESET " ");
    fflush(stdout);
    Flow *f = flow_by_key(read_key(-1));
    if (!f || !f->fields[0].key) return;
    printf("%s\n " DIM "Enter keeps a value, - restores the demo value." RESET "\n", f->title);
    for (int i = 0; i < 2 && f->fields[i].key; i++) {
        const Field *fd = &f->fields[i];
        for (;;) {
            char prompt[300], in[200], v[128];
            trim(v, sizeof v, raw_value(f, i));
            snprintf(prompt, sizeof prompt, "   %s%s%s%s [%s]: ", fd->label, *fd->suffix ? " (" : "", fd->suffix,
                     *fd->suffix ? ")" : "", v);
            if (!prompt_line(prompt, in, sizeof in)) return;
            trim(v, sizeof v, in);
            if (!v[0]) break;
            if (!strcmp(v, "-")) {
                f->value[i][0] = 0;
                break;
            }
            const char *why = strlen(v) >= sizeof f->value[i] ? "too long" : check_field(fd, v, NULL, NULL);
            if (!why) {
                memcpy(f->value[i], v, strlen(v) + 1); /* fits: checked above */
                break;
            }
            printf("   " RED "%s" RESET "\n", why);
        }
    }
    snprintf(S.msg, sizeof S.msg, "%s: values updated.", f->title);
}

static void edit_safe(void)
{
    char h[41], prompt[160], in[200], v[128];
    printf("\n\n " BOLD "Safe address" RESET " for the Safe demos 1-3. " DIM
           "Enter keeps it, - restores the demo Safe." RESET "\n");
    for (;;) {
        Addr a;
        hex(h, S.safe.b, 20);
        snprintf(prompt, sizeof prompt, "   Safe [0x%s]: ", h);
        if (!prompt_line(prompt, in, sizeof in)) return;
        trim(v, sizeof v, in);
        if (!v[0]) return;
        const char *why = NULL;
        if (strcmp(v, "-")) why = parse_addr(v, &a);
        else a = A(DEMO_SAFE);
        if (!why) {
            S.safe = a;
            save_state();
            snprintf(S.msg, sizeof S.msg, "Safe address set.");
            return;
        }
        printf("   " RED "%s" RESET "\n", why);
    }
}

static void on_key(int k)
{
    Flow *f = flow_by_key(k);
    S.dirty = true;
    switch (k) {
    case KEY_CTRL_C:
    case KEY_EOF:
    case 'q':
    case 'Q': quit();
    case KEY_ESC: /* leave the stage; cancels a demo still waiting for PQ1 */
        S.active = NULL;
        S.msg[0] = 0;
        return;
    case 'e':
    case 'E': edit_amounts(); return;
    case 's':
    case 'S': edit_safe(); return;
    case 'r':
    case 'R':
        S.take = 0;
        save_state();
        snprintf(S.msg, sizeof S.msg, "Counter reset: the next request uses UserOp nonce 0 and Safe nonce 17.");
        return;
    }
    if (!f) return;
    S.active = f; /* it starts as soon as PQ1 is connected and unlocked */
    S.phase = PHASE_PENDING;
    S.note[0] = 0;
    S.msg[0] = 0;
}

/* ── self-test: every request byte-identical to android-demo's goldens ───────────────────── */

static int g_fails;

static void expect_bytes(const char *what, const uint8_t *got, size_t gn, const uint8_t *want, size_t wn)
{
    size_t i = 0;
    while (i < gn && i < wn && got[i] == want[i]) i++;
    bool ok = gn == wn && i == gn;
    printf("%s  %-28s %5zu B", ok ? "PASS" : "FAIL", what, gn);
    if (!ok) printf("   want %zu B, first difference at byte %zu", wn, i);
    putchar('\n');
    g_fails += !ok;
}

static void expect_str(const char *what, const char *got, const char *want)
{
    bool ok = got && !strcmp(got, want);
    printf("%s  %-28s %s\n", ok ? "PASS" : "FAIL", what, got ? got : "(none)");
    g_fails += !ok;
}

static bool read_file(const char *dir, const char *name, Buf *b)
{
    char path[1024];
    snprintf(path, sizeof path, "%s/%s.bin", dir, name);
    FILE *f = fopen(path, "rb");
    if (!f) return false;
    b->n = fread(b->b, 1, CAP, f);
    fclose(f);
    return true;
}

static Flow *flow_by_id(const char *id)
{
    for (size_t i = 0; i < NFLOWS; i++)
        if (!strcmp(FLOWS[i].id, id)) return &FLOWS[i];
    die("internal: no flow %s", id);
}

static void set_value(Flow *f, const char *key, const char *v)
{
    snprintf(f->value[field_index(f, key)], sizeof f->value[0], "%s", v);
}

static int selftest(const char *dir)
{
    static Request r;
    static Buf want, got;
    uint8_t h[32], seq[300];
    char hx[65], ab[43] = "0x", cd[43] = "0x", twelves[43] = "0x";
    /* FlowGoldenTest: sender 0x51…51, nonce 3, validTo 1_800_000_000, Safe 0x5afe…01, and the
     * Python scripts' values (the app's own defaults are larger and use other addresses). */
    Ctx c = { .take = 3, .valid_to = 1800000000 };
    memset(c.sender.b, 0x51, 20);
    c.safe.b[0] = 0x5a;
    c.safe.b[1] = 0xfe;
    c.safe.b[19] = 0x01;
    for (int i = 0; i < 20; i++) {
        strcat(ab, "ab");
        strcat(cd, "cd");
        strcat(twelves, "12");
    }
    const struct { const char *flow, *golden, *k1, *v1, *k2, *v2; } cases[] = {
        { "send", "send", "amount", "0.0125", "to", ab },
        { "usdc", "erc20", "amount", "1234.56", "to", cd },
        { "safe_usdc", "safe_usdc", "amount", "250", "to", ab },
        { "safe_cow", "safe_cow", "sell", "0.5", "buy", "1842.31" },
        { "safe_msend", "safe_msend", "sell", "1250", "buy", "1234.987654321098765432" },
        { "cow", "cow", "sell", "0.5", "buy", "1842.31" },
        { "bybit", "bybit", NULL, NULL, NULL, NULL },
    };

    /* KeccakTest.kt: around the 136-byte rate, over bytes i % 251. */
    const struct { size_t n; const char *hash; } rate[] = {
        { 135, "cbdfd9dee5faad3818d6b06f95a219fd290b0e1706f6a82e5a595b9ce9faca62" },
        { 136, "7ce759f1ab7f9ce437719970c26b0a66ff11fe3e38e17df89cf5d29c7d7f807e" },
        { 137, "ac73d4fae68b8453f764007c1a20ce95994187861f0c3227a3a8e99a73a3b1db" },
        { 300, "4699841dafd5e26cca72b05a41d38c96b4b468e5a6cbf694cbebe77dacdf6528" },
    };

    keccak256("", 0, h);
    hex(hx, h, 32);
    expect_str("keccak256('')", hx, "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
    keccak_str("abc", h);
    hex(hx, h, 32);
    expect_str("keccak256('abc')", hx, "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");
    for (size_t i = 0; i < sizeof seq; i++) seq[i] = (uint8_t)(i % 251);
    for (size_t i = 0; i < sizeof rate / sizeof rate[0]; i++) {
        char what[32];
        keccak256(seq, rate[i].n, h);
        hex(hx, h, 32);
        snprintf(what, sizeof what, "keccak256(%zu B)", rate[i].n);
        expect_str(what, hx, rate[i].hash);
    }
    sha256("abc", 3, h);
    hex(hx, h, 32);
    expect_str("sha256('abc')", hx, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    sha256(seq, 300, h);
    hex(hx, h, 32);
    expect_str("sha256(300 B)", hx, "43f9b5d59eb108817176c6f65c2c6203a22f2ae8bc28b7a1dde45947678c5042");

    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        Flow *f = flow_by_id(cases[i].flow);
        if (cases[i].k1) set_value(f, cases[i].k1, cases[i].v1);
        if (cases[i].k2) set_value(f, cases[i].k2, cases[i].v2);
        const char *why = f->build(f, &c, &r);
        if (!read_file(dir, cases[i].golden, &want)) die("cannot read %s/%s.bin", dir, cases[i].golden);
        if (why) printf("FAIL  %s: %s\n", f->id, why), g_fails++;
        else expect_bytes(f->id, r.payload.b, r.payload.n, want.b, want.n);
        memset(f->value, 0, sizeof f->value);
    }
    for (size_t i = 0; i < NFLOWS; i++)
        if (validate(&FLOWS[i])) printf("FAIL  %s defaults: %s\n", FLOWS[i].id, validate(&FLOWS[i])), g_fails++;

    /* HID framing: the first chained APDU of safe_msend (P1=0x80, LC=255) and GET_WALLET_ADDRESS. */
    uint8_t apdu[5 + 255] = { CLA, INS_SIGN_USEROP, P1_MORE, 0, 255 };
    if (!read_file(dir, "safe_msend", &want)) die("cannot read %s/safe_msend.bin", dir);
    memcpy(apdu + 5, want.b, 255);
    got.n = 0;
    frames(apdu, sizeof apdu, &got);
    if (!read_file(dir, "frames_chained_first", &want)) die("cannot read %s/frames_chained_first.bin", dir);
    expect_bytes("frames: chained first block", got.b, got.n, want.b, want.n);
    const uint8_t address[] = { CLA, INS_GET_WALLET_ADDRESS, 0, 0, 4, 0, 0, 0, 0 };
    got.n = 0;
    frames(address, sizeof address, &got);
    if (!read_file(dir, "frames_get_address", &want)) die("cannot read %s/frames_get_address.bin", dir);
    expect_bytes("frames: GET_WALLET_ADDRESS", got.b, got.n, want.b, want.n);

    /* Edited values reach the payload, and bad ones are named. */
    Flow *su = flow_by_id("safe_usdc"), *usdc = flow_by_id("usdc");
    set_value(su, "amount", "900");
    set_value(su, "to", twelves);
    su->build(su, &c, &r);
    got.n = 0;
    put_zeros(&got, 12);
    put(&got, A(twelves).b, 20);
    bool found = false;
    for (size_t i = 0; i + got.n <= r.payload.n && !found; i++) found = !memcmp(r.payload.b + i, got.b, got.n);
    printf("%s  %-28s\n", found ? "PASS" : "FAIL", "edited recipient in payload");
    g_fails += !found;
    memset(su->value, 0, sizeof su->value);
    set_value(usdc, "amount", "1.0000001");
    expect_str("validate amount", validate(usdc), "Amount: at most 6 decimals");
    memset(usdc->value, 0, sizeof usdc->value);
    set_value(usdc, "to", "0x1234");
    expect_str("validate recipient", validate(usdc), "Recipient: not a 20-byte hex address");
    memset(usdc->value, 0, sizeof usdc->value);

    printf(g_fails ? "selftest: %d FAILED\n" : "selftest: all PASS\n", g_fails);
    return g_fails ? 1 : 0;
}

int main(int argc, char **argv)
{
    static char out[1 << 16];
    if (argc == 3 && !strcmp(argv[1], "--selftest")) return selftest(argv[2]);
    if (argc > 1) {
        fprintf(stderr, "usage: %s [--selftest <android-demo golden dir>]\n", argv[0]);
        return 2;
    }
    /* One copy at a time: two would take each other's replies from PQ1. */
    int lock = open(state_path(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (lock >= 0 && flock(lock, LOCK_EX | LOCK_NB) != 0 && errno == EWOULDBLOCK) {
        fprintf(stderr, "PQ1 Demo is already running in another Terminal window.\n");
        return 1;
    }
    setvbuf(stdout, out, _IOFBF, sizeof out);
    load_state();
    S.attempts = -1;
    g_tty = isatty(0) && tcgetattr(0, &g_tty0) == 0;
    atexit(restore_tty);
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGHUP, on_signal);
    tty_raw(true);
    fit_window();
    printf("\x1b]0;PQ1 Demo\x07\x1b[?25l");
    S.dirty = true;
    for (;;) {
        tick();
        if (S.active && S.phase == PHASE_PENDING && S.conn == CONN_UNLOCKED) {
            execute(S.active);
            continue;
        }
        if (S.dirty) render();
        int k = read_key(1000);
        if (k != KEY_NONE) on_key(k);
    }
}
