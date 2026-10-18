// SCE/SELF/PKG decryption + ELF reconstruction + tar + cosunpkg.
// Ported from fail0verflow ps3tools (tools.c sce_decrypt_header/data,
// unself.c, unpkg.c, cosunpkg.c). GPL-2.0, Copyright 2010 Sven Peter.
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

namespace Ps3PupExtractor
{
    // big-endian readers over a byte[]
    static class BE
    {
        public static ushort U16(byte[] b, long o) { return (ushort)((b[o] << 8) | b[o + 1]); }
        public static uint U32(byte[] b, long o) { return ((uint)b[o] << 24) | ((uint)b[o + 1] << 16) | ((uint)b[o + 2] << 8) | b[o + 3]; }
        public static ulong U64(byte[] b, long o)
        {
            ulong r = 0; for (int i = 0; i < 8; i++) r = (r << 8) | b[o + i]; return r;
        }
        public static void W32(byte[] b, long o, uint v) { b[o] = (byte)(v >> 24); b[o + 1] = (byte)(v >> 16); b[o + 2] = (byte)(v >> 8); b[o + 3] = (byte)v; }
        public static void W64(byte[] b, long o, ulong v) { for (int i = 0; i < 8; i++) b[o + 7 - i] = (byte)(v >> (i * 8)); }
    }

    static class Crypto
    {
        static Aes NewAes(byte[] key)
        {
            var a = Aes.Create();
            a.Mode = CipherMode.ECB;
            a.Padding = PaddingMode.None;
            a.KeySize = key.Length * 8;
            a.Key = key;
            return a;
        }

        // AES-CBC decrypt in place over [off, off+len) (len multiple of 16). key 16 or 32 bytes.
        public static void CbcDecrypt(byte[] key, byte[] ivIn, byte[] buf, long off, long len)
        {
            using (var a = Aes.Create())
            {
                a.Mode = CipherMode.CBC; a.Padding = PaddingMode.None;
                a.KeySize = key.Length * 8; a.Key = key; a.IV = (byte[])ivIn.Clone();
                using (var dec = a.CreateDecryptor())
                {
                    byte[] slice = new byte[len];
                    Array.Copy(buf, off, slice, 0, len);
                    byte[] outp = dec.TransformFinalBlock(slice, 0, (int)len);
                    Array.Copy(outp, 0, buf, off, len);
                }
            }
        }

        public static byte[] CbcDecryptCopy(byte[] key, byte[] ivIn, byte[] src, long off, int len)
        {
            byte[] outp;
            using (var a = Aes.Create())
            {
                a.Mode = CipherMode.CBC; a.Padding = PaddingMode.None;
                a.KeySize = key.Length * 8; a.Key = key; a.IV = (byte[])ivIn.Clone();
                using (var dec = a.CreateDecryptor())
                {
                    byte[] slice = new byte[len];
                    Array.Copy(src, off, slice, 0, len);
                    outp = dec.TransformFinalBlock(slice, 0, len);
                }
            }
            return outp;
        }

        // AES-128-CTR in place, big-endian counter in low 64 bits w/ carry (matches tools.c).
        public static void Ctr128(byte[] key, byte[] ivIn, byte[] buf, long off, long len)
        {
            byte[] iv = (byte[])ivIn.Clone();
            using (var a = NewAes(key))
            using (var enc = a.CreateEncryptor())
            {
                byte[] ctr = new byte[16];
                byte[] blk = new byte[16];
                for (long i = 0; i < len; i++)
                {
                    if ((i & 0xf) == 0)
                    {
                        enc.TransformBlock(iv, 0, 16, ctr, 0);
                        ulong lo = BE.U64(iv, 8) + 1;
                        BE.W64(iv, 8, lo);
                        if (lo == 0) BE.W64(iv, 0, BE.U64(iv, 0) + 1);
                    }
                    buf[off + i] ^= ctr[i & 0xf];
                }
            }
        }

        // single-block AES-128 ECB decrypt / encrypt (npdrm helpers; unused for firmware)
        public static void Ecb128Dec(byte[] key, byte[] inb, byte[] outb)
        {
            using (var a = NewAes(key)) using (var d = a.CreateDecryptor()) d.TransformBlock(inb, 0, 16, outb, 0);
        }
    }

    static class Zlib
    {
        // zlib (RFC1950) inflate: skip 2-byte header, raw-inflate the rest.
        public static byte[] Inflate(byte[] input, long off, long len, int outLen)
        {
            byte[] outp = new byte[outLen];
            using (var ms = new MemoryStream(input, (int)(off + 2), (int)(len - 2)))
            using (var ds = new DeflateStream(ms, CompressionMode.Decompress))
            {
                int total = 0, r;
                while (total < outLen && (r = ds.Read(outp, total, outLen - total)) > 0) total += r;
            }
            return outp;
        }
    }

    public static class Sce
    {
        const uint SCE_MAGIC = 0x53434500;

        public static bool IsSce(byte[] b) { return b.Length >= 4 && BE.U32(b, 0) == SCE_MAGIC; }

        // ---- sce_decrypt_header (tools.c) : tries each keyset, decrypts metadata in place ----
        static bool DecryptHeader(byte[] ptr, Keyset[] keys)
        {
            long metaOff = BE.U32(ptr, 0x0c);
            ulong headerLen = BE.U64(ptr, 0x10);
            int matched = -1;
            byte[] tmp = null;

            for (int i = 0; i < keys.Length; i++)
            {
                byte[] dec = Crypto.CbcDecryptCopy(keys[i].Erk, keys[i].Riv, ptr, metaOff + 0x20, 0x40);
                bool ok = true;
                for (int j = 0x10; j < 0x20; j++) if (dec[j] != 0) ok = false;
                for (int j = 0x30; j < 0x40; j++) if (dec[j] != 0) ok = false;
                if (ok) { Array.Copy(dec, 0, ptr, metaOff + 0x20, 0x40); tmp = dec; matched = i; break; }
            }
            if (matched < 0) return false;

            // CTR key = decrypted bytes at meta+0x20 (0x10), iv = meta+0x40 (0x10), one continuous stream
            byte[] ctrKey = new byte[16];
            Array.Copy(ptr, metaOff + 0x20, ctrKey, 0, 16);
            byte[] ctrIv = new byte[16];
            Array.Copy(ptr, metaOff + 0x40, ctrIv, 0, 16);
            long metaLen = (long)headerLen - metaOff;
            Crypto.Ctr128(ctrKey, ctrIv, ptr, metaOff + 0x60, metaLen - 0x60);
            return true;
        }

        // ---- sce_decrypt_data (tools.c) : decrypt each data section in place ----
        static void DecryptData(byte[] ptr)
        {
            long metaOff = BE.U32(ptr, 0x0c);
            uint nHdr = BE.U32(ptr, metaOff + 0x60 + 0xc);
            long keysBase = metaOff + 0x80 + 0x30 * nHdr;
            for (uint i = 0; i < nHdr; i++)
            {
                long t = metaOff + 0x80 + 0x30 * i;
                ulong offset = BE.U64(ptr, t);
                ulong size = BE.U64(ptr, t + 8);
                uint keyid = BE.U32(ptr, t + 0x24);
                uint ivid = BE.U32(ptr, t + 0x28);
                if (keyid == 0xffffffff || ivid == 0xffffffff) continue;
                byte[] key = new byte[16]; Array.Copy(ptr, keysBase + keyid * 0x10, key, 0, 16);
                byte[] iv = new byte[16]; Array.Copy(ptr, keysBase + ivid * 0x10, iv, 0, 16);
                Crypto.Ctr128(key, iv, ptr, (long)offset, (long)size);
            }
        }

        static Keyset[] KeysForSelf(byte[] buf)
        {
            long infoOff = (long)BE.U64(buf, 0x28);
            uint appType = BE.U32(buf, infoOff + 0x0c);
            return KeyDb.SelfKeys((int)appType);
        }

        // decrypt a SELF or PKG SCE in place; returns false if no key matched (and it needed one)
        public static bool DecryptInPlace(byte[] buf, bool isPkg)
        {
            ushort keyRev = BE.U16(buf, 0x08);
            if (keyRev == 0x8000) return true; // already decrypted / debug
            Keyset[] keys = isPkg ? KeyDb.PkgKeys : KeysForSelf(buf);
            if (!DecryptHeader(buf, keys)) return false;
            DecryptData(buf);
            return true;
        }

        // ---- unpkg content extraction (unpkg.c) ----
        public static byte[] UnpkgContent(byte[] pkg)
        {
            ushort type = BE.U16(pkg, 0x0a);
            if (type != 3) throw new Exception("not a .pkg SCE (type " + type + ")");
            if (!DecryptInPlace(pkg, true)) throw new Exception("pkg: no key matched");
            long metaOff = BE.U32(pkg, 0x0c);
            ulong decSize = BE.U64(pkg, 0x18);
            long t = metaOff + 0x80 + 0x30 * 2; // section 2 = content
            ulong offset = BE.U64(pkg, t);
            ulong size = BE.U64(pkg, t + 8);
            uint compressed = BE.U32(pkg, t + 0x2c);
            if (compressed == 2)
            {
                int outLen = (int)(decSize - 0x80);
                return Zlib.Inflate(pkg, (long)offset, (long)size, outLen);
            }
            byte[] outp = new byte[size];
            Array.Copy(pkg, (long)offset, outp, 0, (long)size);
            return outp;
        }

        // ---- cosunpkg (cosunpkg.c) ----
        public static List<KeyValuePair<string, byte[]>> CosUnpack(byte[] pkg)
        {
            var res = new List<KeyValuePair<string, byte[]>>();
            uint nFiles = BE.U32(pkg, 4);
            for (uint i = 0; i < nFiles; i++)
            {
                long p = 0x10 + 0x30 * i;
                ulong offset = BE.U64(pkg, p);
                ulong size = BE.U64(pkg, p + 8);
                int nl = 0; while (nl < 0x20 && pkg[p + 0x10 + nl] != 0) nl++;
                string name = Encoding.ASCII.GetString(pkg, (int)(p + 0x10), nl);
                byte[] data = new byte[size];
                Array.Copy(pkg, (long)offset, data, 0, (long)size);
                res.Add(new KeyValuePair<string, byte[]>(name, data));
            }
            return res;
        }

        // ================= SELF -> ELF (unself.c) =================
        class ElfHdr { public byte[] ident = new byte[16]; public bool arch64; public ushort phnum; public ushort phentsize; public ushort shnum; }
        class SelfSec { public uint idx; public ulong offset, size, next; public bool compressed; }
        class OutSec { public long selfOff; public long size; public bool compressed; public long sizeUncomp; public long elfOff; }

        static ElfHdr ReadElfHdr(byte[] buf, long elfOff)
        {
            var h = new ElfHdr();
            Array.Copy(buf, elfOff, h.ident, 0, 16);
            h.arch64 = h.ident[4] == 2;
            if (h.arch64) { h.phentsize = BE.U16(buf, elfOff + 0x36); h.phnum = BE.U16(buf, elfOff + 0x38); h.shnum = BE.U16(buf, elfOff + 0x3c); }
            else { h.phentsize = BE.U16(buf, elfOff + 0x2a); h.phnum = BE.U16(buf, elfOff + 0x2c); h.shnum = BE.U16(buf, elfOff + 0x30); }
            return h;
        }
        static void ReadPhdr(byte[] buf, bool arch64, long p, out ulong pOff, out ulong pFilesz)
        {
            if (arch64) { pOff = BE.U64(buf, p + 1 * 8); pFilesz = BE.U64(buf, p + 4 * 8); }
            else { pOff = BE.U32(buf, p + 1 * 4); pFilesz = BE.U32(buf, p + 4 * 4); }
        }

        public static byte[] SelfToElf(byte[] self)
        {
            if (!IsSce(self)) throw new Exception("not a SELF");

            ushort keyRev = BE.U16(self, 0x08);
            long metaOff = BE.U32(self, 0x0c);
            ulong headerLen = BE.U64(self, 0x10);
            ulong filesize = BE.U64(self, 0x18);
            long elfOff = (long)BE.U64(self, 0x30);
            long phdrOff = (long)BE.U64(self, 0x38) - elfOff;
            long secOff = (long)BE.U64(self, 0x48);

            ElfHdr ehdr = ReadElfHdr(self, elfOff);

            // read section info table (0x20 stride), keep only compressed entries
            var s = new List<SelfSec>();
            for (int i = 0; i < ehdr.phnum; i++)
            {
                long ptr = secOff + (long)i * 0x20;
                var sec = new SelfSec();
                sec.idx = (uint)i;
                sec.offset = BE.U64(self, ptr + 0x00);
                sec.size = BE.U64(self, ptr + 0x08);
                sec.compressed = BE.U32(self, ptr + 0x10) == 2;
                sec.next = BE.U64(self, ptr + 0x20);
                if (sec.compressed) s.Add(sec);
            }
            s.Sort((a, b) => a.offset.CompareTo(b.offset));

            if (keyRev != 0x8000)
            {
                if (!DecryptInPlace(self, false))
                    throw new Exception("SELF: no key matched (type " + BE.U32(self, (long)BE.U64(self, 0x28) + 0x0c) + ")");
            }

            // reconstruct layout
            var outs = new List<OutSec>();
            long curElf = 0;
            long selfOffset = (long)headerLen;
            int si = 0;
            int nSecs = s.Count;
            while (curElf < (long)filesize)
            {
                var o = new OutSec();
                if (si == nSecs)
                {
                    o.selfOff = selfOffset; o.size = (long)filesize - curElf; o.compressed = false;
                    o.sizeUncomp = o.size; o.elfOff = curElf; curElf = (long)filesize;
                }
                else if (selfOffset == (long)s[si].offset)
                {
                    o.selfOff = selfOffset; o.size = (long)s[si].size; o.compressed = true;
                    ulong pOff, pFilesz; ReadPhdr(self, ehdr.arch64, elfOff + phdrOff + (long)ehdr.phentsize * s[si].idx, out pOff, out pFilesz);
                    o.sizeUncomp = (long)pFilesz; o.elfOff = (long)pOff;
                    curElf = (long)pOff + (long)pFilesz; selfOffset = (long)s[si].next; si++;
                }
                else
                {
                    ulong pOff, pFilesz; ReadPhdr(self, ehdr.arch64, elfOff + phdrOff + (long)ehdr.phentsize * s[si].idx, out pOff, out pFilesz);
                    o.selfOff = selfOffset; o.size = (long)pOff - curElf; o.compressed = false;
                    o.sizeUncomp = o.size; o.elfOff = curElf;
                    curElf += o.size; selfOffset += (long)s[si].offset - selfOffset;
                }
                outs.Add(o);
            }

            // write out
            using (var ms = new MemoryStream())
            {
                foreach (var o in outs)
                {
                    ms.Seek(o.elfOff, SeekOrigin.Begin);
                    if (o.compressed)
                    {
                        byte[] d = Zlib.Inflate(self, o.selfOff, o.size, (int)o.sizeUncomp);
                        ms.Write(d, 0, d.Length);
                    }
                    else
                    {
                        ms.Write(self, (int)o.selfOff, (int)o.size);
                    }
                }
                byte[] outElf = ms.ToArray();
                CheckElf(self, outElf, elfOff, ehdr, ref outElf);
                return outElf;
            }
        }

        // check_elf (unself.c): if the reconstructed file lacks an ELF header, rebuild phdr/shdr.
        static void CheckElf(byte[] self, byte[] cur, long elfOff, ElfHdr ehdr, ref byte[] result)
        {
            if (cur.Length >= 4 && cur[0] == 0x7f && cur[1] == (byte)'E' && cur[2] == (byte)'L' && cur[3] == (byte)'F')
            { result = cur; return; }

            long phdrOff = (long)BE.U64(self, 0x38) - elfOff;
            long shdrOff = (long)BE.U64(self, 0x40) - elfOff;
            byte[] elf = self; long e = elfOff; // elf header lives in self buffer at elfOff
            string shstr = ".unknown\0\0";
            byte[] shstrBytes = Encoding.ASCII.GetBytes(shstr);

            using (var ms = new MemoryStream())
            {
                ms.Write(cur, 0, cur.Length);
                if (ehdr.arch64)
                {
                    long phdrNew = 0x48;
                    long shdrNew = cur.Length;
                    ushort nPhdr = BE.U16(elf, e + 0x38);
                    ushort nShdr = BE.U16(elf, e + 0x3c);
                    long shstrOff = shdrNew + (long)nShdr * 0x40;
                    RemoveShNames(elf, e, shdrOff, nShdr, shstrOff, shstrBytes.Length, true);
                    ms.Seek(phdrNew, SeekOrigin.Begin); ms.Write(elf, (int)(e + phdrOff), 0x38 * nPhdr);
                    ms.Seek(shdrNew, SeekOrigin.Begin); ms.Write(elf, (int)(e + shdrOff), 0x40 * nShdr);
                    BE.W64(elf, e + 0x20, (ulong)phdrNew); BE.W64(elf, e + 0x28, (ulong)shdrNew);
                    ms.Seek(0, SeekOrigin.Begin); ms.Write(elf, (int)e, 0x48);
                    ms.Seek(shstrOff, SeekOrigin.Begin); ms.Write(shstrBytes, 0, shstrBytes.Length);
                }
                else
                {
                    long phdrNew = 0x34;
                    long shdrNew = cur.Length;
                    ushort nPhdr = BE.U16(elf, e + 0x2c);
                    ushort nShdr = BE.U16(elf, e + 0x30);
                    long shstrOff = shdrNew + (long)nShdr * 0x40;
                    RemoveShNames(elf, e, shdrOff, nShdr, shstrOff, shstrBytes.Length, false);
                    ms.Seek(phdrNew, SeekOrigin.Begin); ms.Write(elf, (int)(e + phdrOff), 0x20 * nPhdr);
                    ms.Seek(shdrNew, SeekOrigin.Begin); ms.Write(elf, (int)(e + shdrOff), 0x28 * nShdr);
                    BE.W32(elf, e + 0x1c, (uint)phdrNew); BE.W32(elf, e + 0x20, (uint)shdrNew);
                    ms.Seek(0, SeekOrigin.Begin); ms.Write(elf, (int)e, 0x34);
                    ms.Seek(shstrOff, SeekOrigin.Begin); ms.Write(shstrBytes, 0, shstrBytes.Length);
                }
                result = ms.ToArray();
            }
        }

        static void RemoveShNames(byte[] elf, long e, long shdrOff, ushort nShdr, long shstrOff, int strSize, bool arch64)
        {
            int sz = arch64 ? 0x40 : 0x28;
            for (int i = 0; i < nShdr; i++)
            {
                long sh = e + shdrOff + (long)i * sz;
                BE.W32(elf, sh + 0, 0); // sh_name = 0
                uint shType = BE.U32(elf, sh + 4);
                if (shType == 3)
                {
                    if (arch64) { BE.W64(elf, sh + 0x18, (ulong)shstrOff); BE.W64(elf, sh + 0x20, (ulong)strSize); }
                    else { BE.W32(elf, sh + 0x10, (uint)shstrOff); BE.W32(elf, sh + 0x14, (uint)strSize); }
                }
            }
        }
    }

    // minimal POSIX/ustar tar extractor
    public static class Tar
    {
        public static int Extract(byte[] tar, string outDir)
        {
            int count = 0; long pos = 0;
            while (pos + 512 <= tar.Length)
            {
                bool zero = true;
                for (int i = 0; i < 512; i++) if (tar[pos + i] != 0) { zero = false; break; }
                if (zero) break;

                string name = CStr(tar, pos, 100);
                string prefix = CStr(tar, pos + 345, 155);
                if (prefix.Length > 0) name = prefix + "/" + name;
                long size = Octal(tar, pos + 124, 12);
                byte typeflag = tar[pos + 156];
                pos += 512;

                if (typeflag == (byte)'5' || name.EndsWith("/"))
                {
                    try { Directory.CreateDirectory(Path.Combine(outDir, name.Replace('/', Path.DirectorySeparatorChar))); } catch { }
                }
                else if (typeflag == 0 || typeflag == (byte)'0' || typeflag == (byte)'7')
                {
                    string full = Path.Combine(outDir, name.Replace('/', Path.DirectorySeparatorChar));
                    string dir = Path.GetDirectoryName(full);
                    if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                    using (var fo = new FileStream(full, FileMode.Create, FileAccess.Write))
                        fo.Write(tar, (int)pos, (int)size);
                    count++;
                }
                // advance past data, padded to 512
                pos += (size + 511) & ~511L;
            }
            return count;
        }

        static string CStr(byte[] b, long off, int max)
        {
            int n = 0; while (n < max && off + n < b.Length && b[off + n] != 0) n++;
            return Encoding.ASCII.GetString(b, (int)off, n);
        }
        static long Octal(byte[] b, long off, int len)
        {
            long v = 0;
            for (int i = 0; i < len; i++)
            {
                byte c = b[off + i];
                if (c == 0 || c == ' ') continue;
                if (c < '0' || c > '7') break;
                v = v * 8 + (c - '0');
            }
            return v;
        }
    }
}
