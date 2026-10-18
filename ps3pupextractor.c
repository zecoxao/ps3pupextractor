/*
 * ps3pupextractor - PlayStation 3 firmware update (PUP) unpacker
 *
 * Self-contained: embeds the pup-hmac key, implements SHA-1 / HMAC-SHA1
 * inline, needs no external key files or libraries.
 *
 * Format and id->name table based on fail0verflow's ps3tools
 * (pupunpack.c / puppack.c, Copyright 2010 Sven Peter, GPL-2.0).
 * pup-hmac key value from the public ps3keys / scetool key sets.
 *
 * Build (native Linux):   gcc -O2 -o ps3pupextractor ps3pupextractor.c
 * Build (Windows .exe):   x86_64-w64-mingw32-gcc -O2 -o ps3pupextractor.exe ps3pupextractor.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>

#ifdef _WIN32
  #include <direct.h>
  #define MKDIR(p) _mkdir(p)
  #define FSEEK64(f,o,w) _fseeki64((f),(o),(w))
  #define FTELL64(f)     _ftelli64((f))
#else
  #include <sys/types.h>
  #define MKDIR(p) mkdir((p), 0777)
  #define FSEEK64(f,o,w) fseeko((f),(off_t)(o),(w))
  #define FTELL64(f)     ftello((f))
#endif

typedef uint8_t  u8;
typedef uint32_t u32;
typedef uint64_t u64;

/* ------------------------------------------------------------------ */
/* pup-hmac key (0x40 bytes) - identical across ps3keys / scetool sets */
/* ------------------------------------------------------------------ */
static const u8 PUP_HMAC_KEY[0x40] = {
    0xF4,0x91,0xAD,0x94,0xC6,0x81,0x10,0x96,0x91,0x5F,0xD5,0xD2,0x44,0x81,0xAE,0xDC,
    0xED,0xED,0xBE,0x6B,0xE5,0x13,0x72,0x4D,0xD8,0xF7,0xB6,0x91,0xE8,0x8A,0x38,0xF4,
    0xB5,0x16,0x2B,0xFB,0xEC,0xBE,0x3A,0x62,0x18,0x5D,0xD7,0xC9,0x4D,0xA2,0x22,0x5A,
    0xDA,0x3F,0xBF,0xCE,0x55,0x5B,0x9E,0xA9,0x64,0x98,0x29,0xEB,0x30,0xCE,0x83,0x66
};

/* ------------------------------------------------------------------ */
/* SHA-1 (incremental)                                                */
/* ------------------------------------------------------------------ */
typedef struct {
    u32 h[5];
    u64 len;            /* total message length in bytes */
    u8  buf[64];
    u32 buf_len;
} sha1_ctx;

#define ROL32(x,n) (((x) << (n)) | ((x) >> (32 - (n))))

static void sha1_block(sha1_ctx *c, const u8 *p)
{
    u32 w[80], a, b, cc, d, e, t;
    int i;

    for (i = 0; i < 16; i++)
        w[i] = ((u32)p[i*4] << 24) | ((u32)p[i*4+1] << 16) |
               ((u32)p[i*4+2] << 8) | (u32)p[i*4+3];
    for (i = 16; i < 80; i++)
        w[i] = ROL32(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);

    a = c->h[0]; b = c->h[1]; cc = c->h[2]; d = c->h[3]; e = c->h[4];

    for (i = 0; i < 80; i++) {
        u32 f, k;
        if (i < 20)      { f = (b & cc) | ((~b) & d);        k = 0x5A827999; }
        else if (i < 40) { f = b ^ cc ^ d;                   k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & cc) | (b & d) | (cc & d);k = 0x8F1BBCDC; }
        else             { f = b ^ cc ^ d;                   k = 0xCA62C1D6; }
        t = ROL32(a,5) + f + e + k + w[i];
        e = d; d = cc; cc = ROL32(b,30); b = a; a = t;
    }

    c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d; c->h[4] += e;
}

static void sha1_init(sha1_ctx *c)
{
    c->h[0] = 0x67452301; c->h[1] = 0xEFCDAB89; c->h[2] = 0x98BADCFE;
    c->h[3] = 0x10325476; c->h[4] = 0xC3D2E1F0;
    c->len = 0; c->buf_len = 0;
}

static void sha1_update(sha1_ctx *c, const u8 *data, size_t len)
{
    c->len += len;
    while (len > 0) {
        u32 n = 64 - c->buf_len;
        if (n > len) n = (u32)len;
        memcpy(c->buf + c->buf_len, data, n);
        c->buf_len += n; data += n; len -= n;
        if (c->buf_len == 64) { sha1_block(c, c->buf); c->buf_len = 0; }
    }
}

static void sha1_final(sha1_ctx *c, u8 out[20])
{
    u64 bits = c->len * 8;
    u8 pad = 0x80;
    u8 lenbuf[8];
    int i;

    sha1_update(c, &pad, 1);
    pad = 0x00;
    while (c->buf_len != 56) sha1_update(c, &pad, 1);
    for (i = 0; i < 8; i++) lenbuf[i] = (u8)(bits >> (56 - i*8));
    sha1_update(c, lenbuf, 8);
    for (i = 0; i < 5; i++) {
        out[i*4]   = (u8)(c->h[i] >> 24);
        out[i*4+1] = (u8)(c->h[i] >> 16);
        out[i*4+2] = (u8)(c->h[i] >> 8);
        out[i*4+3] = (u8)(c->h[i]);
    }
}

/* ------------------------------------------------------------------ */
/* HMAC-SHA1 (incremental)                                            */
/* ------------------------------------------------------------------ */
typedef struct {
    sha1_ctx inner;
    u8       okey[64];
} hmac_ctx;

static void hmac_init(hmac_ctx *h, const u8 *key, size_t keylen)
{
    u8 k[64];
    u8 ikey[64];
    int i;

    memset(k, 0, sizeof k);
    if (keylen > 64) {
        sha1_ctx t; u8 d[20];
        sha1_init(&t); sha1_update(&t, key, keylen); sha1_final(&t, d);
        memcpy(k, d, 20);
    } else {
        memcpy(k, key, keylen);
    }
    for (i = 0; i < 64; i++) { ikey[i] = k[i] ^ 0x36; h->okey[i] = k[i] ^ 0x5c; }
    sha1_init(&h->inner);
    sha1_update(&h->inner, ikey, 64);
}

static void hmac_update(hmac_ctx *h, const u8 *data, size_t len)
{
    sha1_update(&h->inner, data, len);
}

static void hmac_final(hmac_ctx *h, u8 out[20])
{
    u8 idig[20];
    sha1_ctx outer;
    sha1_final(&h->inner, idig);
    sha1_init(&outer);
    sha1_update(&outer, h->okey, 64);
    sha1_update(&outer, idig, 20);
    sha1_final(&outer, out);
}

/* ------------------------------------------------------------------ */
/* helpers                                                            */
/* ------------------------------------------------------------------ */
static u64 be64(const u8 *p)
{
    return ((u64)p[0] << 56) | ((u64)p[1] << 48) | ((u64)p[2] << 40) |
           ((u64)p[3] << 32) | ((u64)p[4] << 24) | ((u64)p[5] << 16) |
           ((u64)p[6] << 8)  |  (u64)p[7];
}

static const char *id2name(u64 id)
{
    switch (id) {
        case 0x100: return "version.txt";
        case 0x101: return "license.xml";
        case 0x102: return "promo_flags.txt";
        case 0x103: return "update_flags.txt";
        case 0x104: return "patch_build.txt";
        case 0x200: return "ps3swu.self";
        case 0x201: return "vsh.tar";
        case 0x202: return "dots.txt";
        case 0x203: return "patch_data.pkg";
        case 0x300: return "update_files.tar";
        case 0x501: return "spkg_hdr.tar";
        case 0x601: return "ps3swu2.self";
        default:    return NULL;
    }
}

#define CHUNK (1u << 20)   /* 1 MiB streaming buffer */

/* Stream `len` bytes starting at `off`: HMAC them and (optionally) write
 * them to `out`. Returns 0 on success, -1 on read/write error. */
static int stream_section(FILE *in, u64 off, u64 len, hmac_ctx *hm, FILE *out,
                          u8 *buf)
{
    if (FSEEK64(in, off, SEEK_SET) != 0) return -1;
    while (len > 0) {
        size_t want = (len < CHUNK) ? (size_t)len : CHUNK;
        size_t got  = fread(buf, 1, want, in);
        if (got == 0) return -1;
        if (hm)  hmac_update(hm, buf, got);
        if (out && fwrite(buf, 1, got, out) != got) return -1;
        len -= got;
    }
    return 0;
}

static void hexline(const u8 *p, int n, char *out)
{
    static const char hx[] = "0123456789abcdef";
    int i;
    for (i = 0; i < n; i++) { out[i*2] = hx[p[i] >> 4]; out[i*2+1] = hx[p[i] & 0xf]; }
    out[n*2] = 0;
}

/* ------------------------------------------------------------------ */
int main(int argc, char *argv[])
{
    const char *inpath, *outdir;
    char defdir[1024];
    FILE *in;
    u8 base[0x30];
    u8 *tbl = NULL;          /* entry table + hash table */
    u64 n, hdr_size, data_size, img_ver, pkg_ver;
    u64 tbl_off = 0x30, tbl_len, i;
    u8 *buf = NULL;
    int ok_count = 0, fail_count = 0, unk_count = 0;
    int rc = 1;

    printf("ps3pupextractor - PS3 firmware PUP unpacker\n");

    if (argc < 2 || argc > 3) {
        fprintf(stderr, "usage: %s <PS3UPDAT.PUP> [output_dir]\n", argv[0]);
        return 1;
    }
    inpath = argv[1];

    in = fopen(inpath, "rb");
    if (!in) { fprintf(stderr, "error: cannot open '%s'\n", inpath); return 1; }

    if (fread(base, 1, 0x30, in) != 0x30) {
        fprintf(stderr, "error: file too small / read failed\n"); goto done;
    }
    if (memcmp(base, "SCEUF\0\0\0", 8) != 0) {
        fprintf(stderr, "error: not a PUP (bad magic 'SCEUF')\n"); goto done;
    }

    pkg_ver   = be64(base + 0x08);
    img_ver   = be64(base + 0x10);
    n         = be64(base + 0x18);
    hdr_size  = be64(base + 0x20);
    data_size = be64(base + 0x28);

    if (n == 0 || n > 4096) {
        fprintf(stderr, "error: implausible file count %llu\n",
                (unsigned long long)n); goto done;
    }

    printf("  package version : %llu\n", (unsigned long long)pkg_ver);
    printf("  image version   : 0x%llX (build %llu)\n",
           (unsigned long long)img_ver, (unsigned long long)img_ver);
    printf("  files           : %llu\n", (unsigned long long)n);
    printf("  header size     : 0x%llX\n", (unsigned long long)hdr_size);
    printf("  data size       : 0x%llX\n\n", (unsigned long long)data_size);

    /* entry table (0x20 * n) + hash table (0x20 * n) */
    tbl_len = 0x40 * n;
    tbl = (u8 *)malloc((size_t)tbl_len);
    if (!tbl) { fprintf(stderr, "error: out of memory\n"); goto done; }
    if (FSEEK64(in, tbl_off, SEEK_SET) != 0 ||
        fread(tbl, 1, (size_t)tbl_len, in) != tbl_len) {
        fprintf(stderr, "error: cannot read entry/hash table\n"); goto done;
    }

    buf = (u8 *)malloc(CHUNK);
    if (!buf) { fprintf(stderr, "error: out of memory\n"); goto done; }

    /* ---- verify header HMAC (over first 0x30 + 0x40*n bytes) ---- */
    {
        hmac_ctx hm; u8 calc[20]; const u8 *stored;
        hmac_init(&hm, PUP_HMAC_KEY, sizeof PUP_HMAC_KEY);
        hmac_update(&hm, base, 0x30);
        hmac_update(&hm, tbl, (size_t)tbl_len);   /* entries + hashes */
        hmac_final(&hm, calc);
        /* header hmac sits right after the hash table, at 0x30 + 0x40*n */
        stored = NULL;
        {
            u8 hhmac[20];
            if (FSEEK64(in, tbl_off + tbl_len, SEEK_SET) == 0 &&
                fread(hhmac, 1, 20, in) == 20) {
                int match = (memcmp(calc, hhmac, 20) == 0);
                printf("  header HMAC      : %s\n\n", match ? "OK" : "FAIL");
                if (!match) fail_count++;
                (void)stored;
            } else {
                printf("  header HMAC      : ??? (could not read)\n\n");
            }
        }
    }

    /* ---- determine / create output directory ---- */
    if (argc == 3) {
        outdir = argv[2];
    } else {
        const char *bn = inpath, *p;
        for (p = inpath; *p; p++) if (*p == '/' || *p == '\\') bn = p + 1;
        snprintf(defdir, sizeof defdir, "%s_extracted", bn);
        outdir = defdir;
    }
    if (MKDIR(outdir) != 0) {
        struct stat st;
        if (stat(outdir, &st) != 0) {
            fprintf(stderr, "error: cannot create output dir '%s'\n", outdir);
            goto done;
        }
    }
    printf("Extracting %llu file(s) to: %s\n\n", (unsigned long long)n, outdir);

    /* ---- iterate sections ---- */
    for (i = 0; i < n; i++) {
        const u8 *e = tbl + 0x20 * i;                 /* entry */
        const u8 *h = tbl + 0x20 * n + 0x20 * i + 8;  /* stored hmac (after idx) */
        u64 id   = be64(e + 0x00);
        u64 off  = be64(e + 0x08);
        u64 size = be64(e + 0x10);
        const char *name = id2name(id);
        char fname[64], outpath[2048];
        FILE *out;
        hmac_ctx hm; u8 calc[20]; char hx[48];
        int match;

        if (name) {
            snprintf(fname, sizeof fname, "%s", name);
        } else {
            snprintf(fname, sizeof fname, "0x%llX.bin", (unsigned long long)id);
            unk_count++;
        }
        snprintf(outpath, sizeof outpath, "%s/%s", outdir, fname);

        out = fopen(outpath, "wb");
        if (!out) {
            fprintf(stderr, "  [%llu] %-18s  ERROR: cannot write %s\n",
                    (unsigned long long)i, fname, outpath);
            continue;
        }

        hmac_init(&hm, PUP_HMAC_KEY, sizeof PUP_HMAC_KEY);
        if (stream_section(in, off, size, &hm, out, buf) != 0) {
            fprintf(stderr, "  [%llu] %-18s  ERROR: read/write failed\n",
                    (unsigned long long)i, fname);
            fclose(out);
            continue;
        }
        fclose(out);
        hmac_final(&hm, calc);
        match = (memcmp(calc, h, 20) == 0);
        if (match) ok_count++; else fail_count++;

        hexline(calc, 4, hx);
        printf("  [%llu] id=0x%-4llX %-18s size=0x%-9llX HMAC=%s (%s..)\n",
               (unsigned long long)i, (unsigned long long)id, fname,
               (unsigned long long)size, match ? "OK  " : "FAIL", hx);
    }

    printf("\nDone. sections OK=%d FAIL=%d unknown-id=%d\n",
           ok_count, fail_count, unk_count);
    rc = (fail_count == 0) ? 0 : 2;

done:
    if (buf) free(buf);
    if (tbl) free(tbl);
    fclose(in);
    return rc;
}
