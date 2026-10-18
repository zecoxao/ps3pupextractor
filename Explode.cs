// PUP container split + full "pupexplode" pipeline (untar / unpkg / cosunpkg / SELF->ELF).
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;

namespace Ps3PupExtractor
{
    public static class Pup
    {
        // pup-hmac key (0x40) - identical across ps3keys / scetool key sets
        public static readonly byte[] HmacKey = KeyDb.Hex(
            "F491AD94C681109691" + "5FD5D24481AEDCEDEDBE6BE513724DD8F7B691E88A38F4" +
            "B5162BFBECBE3A62185DD7C94DA2225ADA3FBFCE555B9EA9649829EB30CE8366");

        public class Entry { public ulong Id, Offset, Size; public byte[] Hmac; public string Name; }

        public static string IdName(ulong id)
        {
            switch (id)
            {
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
                default: return string.Format("0x{0:X}.bin", id);
            }
        }

        // Split a PUP into its section files; verify HMAC. Returns entries.
        public static List<Entry> Split(string pupPath, string outDir, bool verify, Action<string> log)
        {
            var entries = new List<Entry>();
            using (var fs = new FileStream(pupPath, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20))
            {
                byte[] baseHdr = new byte[0x30];
                if (ReadFull(fs, baseHdr, 0x30) != 0x30) throw new Exception("file too small");
                if (!(baseHdr[0] == 'S' && baseHdr[1] == 'C' && baseHdr[2] == 'E' && baseHdr[3] == 'U' && baseHdr[4] == 'F'))
                    throw new Exception("not a PUP (bad 'SCEUF' magic)");

                ulong imgVer = BE.U64(baseHdr, 0x10);
                ulong n = BE.U64(baseHdr, 0x18);
                if (n == 0 || n > 4096) throw new Exception("implausible file count " + n);
                log(string.Format("PUP: build {0}, {1} section(s)", imgVer, n));

                int tblLen = (int)(0x40 * n);
                byte[] tbl = new byte[tblLen];
                fs.Seek(0x30, SeekOrigin.Begin);
                if (ReadFull(fs, tbl, tblLen) != tblLen) throw new Exception("cannot read entry/hash table");

                if (verify)
                {
                    byte[] hbuf = new byte[0x30 + tblLen];
                    Buffer.BlockCopy(baseHdr, 0, hbuf, 0, 0x30);
                    Buffer.BlockCopy(tbl, 0, hbuf, 0x30, tblLen);
                    byte[] calc; using (var hm = new HMACSHA1(HmacKey)) calc = hm.ComputeHash(hbuf);
                    byte[] stored = new byte[20]; fs.Seek(0x30 + (long)tblLen, SeekOrigin.Begin); ReadFull(fs, stored, 20);
                    log("  header HMAC: " + (Eq(calc, stored) ? "OK" : "FAIL"));
                }

                Directory.CreateDirectory(outDir);
                byte[] buf = new byte[1 << 20];
                for (ulong i = 0; i < n; i++)
                {
                    int eo = (int)(0x20 * i);
                    var e = new Entry { Id = BE.U64(tbl, eo), Offset = BE.U64(tbl, eo + 8), Size = BE.U64(tbl, eo + 0x10) };
                    e.Name = IdName(e.Id);
                    e.Hmac = new byte[20]; Buffer.BlockCopy(tbl, (int)(0x20 * n + 0x20 * i + 8), e.Hmac, 0, 20);
                    entries.Add(e);

                    string outPath = Path.Combine(outDir, e.Name);
                    fs.Seek((long)e.Offset, SeekOrigin.Begin);
                    HMACSHA1 hm = verify ? new HMACSHA1(HmacKey) : null;
                    using (var o = new FileStream(outPath, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 20))
                    {
                        ulong rem = e.Size;
                        while (rem > 0)
                        {
                            int want = (int)Math.Min((ulong)buf.Length, rem);
                            int got = fs.Read(buf, 0, want); if (got <= 0) break;
                            if (hm != null) hm.TransformBlock(buf, 0, got, null, 0);
                            o.Write(buf, 0, got); rem -= (ulong)got;
                        }
                    }
                    string st = "";
                    if (hm != null) { hm.TransformFinalBlock(new byte[0], 0, 0); st = Eq(hm.Hash, e.Hmac) ? " HMAC OK" : " HMAC FAIL"; hm.Dispose(); }
                    log(string.Format("  [{0}] {1,-18} 0x{2:X}{3}", i, e.Name, e.Size, st));
                }
            }
            return entries;
        }

        static int ReadFull(Stream s, byte[] b, int len) { int t = 0, r; while (t < len && (r = s.Read(b, t, len - t)) > 0) t += r; return t; }
        static bool Eq(byte[] a, byte[] b) { if (a.Length != b.Length) return false; for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) return false; return true; }
    }

    public static class Exploder
    {
        // SELF->ELF filename gate (pupexplode's find patterns)
        static bool IsSelfName(string n)
        {
            n = n.ToLowerInvariant();
            if (n.EndsWith(".elf")) return false;
            return n.EndsWith(".self") || n.EndsWith(".sprx") || n.EndsWith(".isoself")
                || n.EndsWith("ldr") || n.EndsWith("lv0");
        }

        public static void Explode(string pupPath, string outDir, bool doDevFlash, Action<string> log)
        {
            // 1. split container
            Pup.Split(pupPath, outDir, true, log);

            string tarPath = Path.Combine(outDir, "update_files.tar");
            if (!File.Exists(tarPath)) { log("no update_files.tar; container-only PUP."); DecryptSelfsRecursive(outDir, log); return; }

            // 2. untar update_files.tar
            string ufDir = Path.Combine(outDir, "update_files");
            Directory.CreateDirectory(ufDir);
            log("\nUntar update_files.tar ...");
            int nf = Tar.Extract(File.ReadAllBytes(tarPath), ufDir);
            log("  " + nf + " member(s)");

            // 3. unpkg each package in update_files
            foreach (string f in Directory.GetFiles(ufDir))
            {
                string name = Path.GetFileName(f);
                bool isDev = name.StartsWith("dev_flash");
                bool isPkg = name.EndsWith(".pkg");
                if (!isDev && !isPkg) continue;              // skip .img etc. (like pupexplode)
                if (isDev && !doDevFlash) { log("  skip (dev_flash off): " + name); continue; }

                try
                {
                    byte[] pkg = File.ReadAllBytes(f);
                    if (!Sce.IsSce(pkg)) { log("  not SCE: " + name); continue; }

                    if (isDev)
                    {
                        byte[] content = Sce.UnpkgContent(pkg);
                        int c = Tar.Extract(content, ufDir);  // accumulate dev_flash tree
                        log(string.Format("  unpkg+untar {0}: {1} file(s)", name, c));
                    }
                    else
                    {
                        string stem = name.Substring(0, name.Length - 4); // strip .pkg
                        string pdir = Path.Combine(ufDir, stem);
                        Directory.CreateDirectory(pdir);
                        byte[] content = Sce.UnpkgContent(pkg);
                        File.WriteAllBytes(Path.Combine(pdir, "content"), content);

                        if (name == "CORE_OS_PACKAGE.pkg")
                        {
                            var items = Sce.CosUnpack(content);
                            foreach (var kv in items)
                                File.WriteAllBytes(Path.Combine(pdir, kv.Key), kv.Value);
                            log(string.Format("  unpkg+cosunpkg {0}: {1} component(s)", name, items.Count));
                        }
                        else log("  unpkg " + name);
                    }
                }
                catch (Exception ex) { log("  ERROR " + name + ": " + ex.Message); }
            }

            // 4. SELF -> ELF (everything, recursively)
            log("\nDecrypt SELF -> ELF ...");
            DecryptSelfsRecursive(outDir, log);
            log("\nExplode complete.");
        }

        static void DecryptSelfsRecursive(string root, Action<string> log)
        {
            foreach (string f in Directory.GetFiles(root, "*", SearchOption.AllDirectories))
            {
                string name = Path.GetFileName(f);
                if (!IsSelfName(name)) continue;
                try
                {
                    byte[] data = File.ReadAllBytes(f);
                    if (!Sce.IsSce(data)) continue;
                    if (BE.U16(data, 0x0a) != 1) continue;   // header_type 1 == SELF only
                    byte[] elf = Sce.SelfToElf(data);
                    File.WriteAllBytes(f + ".elf", elf);
                    log("  " + Rel(root, f) + " -> .elf");
                }
                catch (Exception ex) { log("  FAIL " + Rel(root, f) + ": " + ex.Message); }
            }
        }

        static string Rel(string root, string f) { return f.Length > root.Length ? f.Substring(root.Length).TrimStart('\\', '/') : f; }
    }
}
