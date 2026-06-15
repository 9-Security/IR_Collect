using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Text;

namespace IR_Collect.Analysis
{
    [DataContract]
    public class EvidenceFile
    {
        [DataMember(Name = "relpath")] public string RelPath { get; set; }
        [DataMember(Name = "size_bytes")] public long SizeBytes { get; set; }
        [DataMember(Name = "sha256")] public string Sha256 { get; set; }
    }

    public sealed class EvidenceManifestResult
    {
        public List<EvidenceFile> Files { get; private set; }
        /// <summary>Single rollup digest over the sorted per-file (relpath, sha256) lines.</summary>
        public string Digest { get; set; }

        public EvidenceManifestResult()
        {
            Files = new List<EvidenceFile>();
            Digest = "";
        }
    }

    /// <summary>
    /// Phase 5.2: builds a SHA-256 evidence manifest for a folder of input artifacts, captured at load
    /// time BEFORE any derivation, so an analysis report can be cryptographically tied back to exactly
    /// the evidence it consumed (court-admissibility). The rollup Digest is a single hash over the sorted
    /// per-file (relpath, sha256) lines - one value that changes if any input file changes.
    /// </summary>
    public static class EvidenceManifest
    {
        public static EvidenceManifestResult HashFolder(string root)
        {
            var result = new EvidenceManifestResult();
            if (string.IsNullOrEmpty(root) || !Directory.Exists(root))
                return result;

            string fullRoot;
            try { fullRoot = Path.GetFullPath(root); } catch { fullRoot = root; }

            var files = new List<EvidenceFile>();
            foreach (string f in SafeEnumerate(fullRoot))
            {
                string rel;
                try
                {
                    string full = Path.GetFullPath(f);
                    rel = full.Length > fullRoot.Length ? full.Substring(fullRoot.Length).TrimStart('\\', '/') : Path.GetFileName(full);
                }
                catch { rel = Path.GetFileName(f); }

                long size = -1;
                string sha;
                try
                {
                    size = new FileInfo(f).Length;
                    sha = ComputeSha256(f);
                }
                catch (Exception ex)
                {
                    sha = "UNREADABLE:" + ex.GetType().Name;
                }
                files.Add(new EvidenceFile { RelPath = rel.Replace('\\', '/'), SizeBytes = size, Sha256 = sha });
            }

            // Deterministic order so the rollup digest is stable regardless of enumeration order.
            files.Sort(delegate (EvidenceFile a, EvidenceFile b)
            {
                return string.Compare(a.RelPath, b.RelPath, StringComparison.OrdinalIgnoreCase);
            });
            result.Files.AddRange(files);
            result.Digest = ComputeRollupDigest(files);
            return result;
        }

        private static IEnumerable<string> SafeEnumerate(string root)
        {
            try { return Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories); }
            catch { return new string[0]; }
        }

        private static string ComputeRollupDigest(List<EvidenceFile> files)
        {
            using (SHA256 sha = SHA256.Create())
            {
                var sb = new StringBuilder();
                foreach (EvidenceFile f in files)
                    sb.Append(f.RelPath).Append('\t').Append(f.Sha256).Append('\n');
                byte[] hash = sha.ComputeHash(Encoding.UTF8.GetBytes(sb.ToString()));
                return ToHex(hash);
            }
        }

        public static string ComputeSha256(string path)
        {
            using (SHA256 sha = SHA256.Create())
            using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                return ToHex(sha.ComputeHash(fs));
            }
        }

        private static string ToHex(byte[] bytes)
        {
            var sb = new StringBuilder(bytes.Length * 2);
            for (int i = 0; i < bytes.Length; i++)
                sb.Append(bytes[i].ToString("x2"));
            return sb.ToString();
        }
    }
}
