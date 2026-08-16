using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Text;
using System.Linq;

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
        public bool IsComplete { get; set; }
        public List<string> Warnings { get; private set; }

        public EvidenceManifestResult()
        {
            Files = new List<EvidenceFile>();
            Digest = "";
            IsComplete = true;
            Warnings = new List<string>();
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
            {
                MarkIncomplete(result, "Evidence root is missing or unavailable.");
                return result;
            }

            string fullRoot;
            try { fullRoot = Path.GetFullPath(root); } catch { fullRoot = root; }
            try
            {
                if (IsRejectedReparsePoint(File.GetAttributes(fullRoot)))
                {
                    MarkIncomplete(result, "Evidence root reparse-point directory was rejected: " +
                        (Path.GetFileName(fullRoot) ?? "(root)"));
                    return result;
                }
            }
            catch (Exception ex)
            {
                MarkIncomplete(result, "Evidence root attributes could not be read (" +
                    ex.GetType().Name + ").");
                return result;
            }

            var files = new List<EvidenceFile>();
            foreach (string f in SafeEnumerate(fullRoot, result))
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
                    var before = new FileInfo(f);
                    size = before.Length;
                    DateTime beforeWrite = before.LastWriteTimeUtc;
                    sha = ComputeSha256(f);
                    var after = new FileInfo(f);
                    if (after.Length != size || after.LastWriteTimeUtc != beforeWrite)
                    {
                        result.IsComplete = false;
                        result.Warnings.Add("Evidence file changed while hashing: " + rel.Replace('\\', '/'));
                    }
                }
                catch (Exception ex)
                {
                    sha = "UNREADABLE:" + ex.GetType().Name;
                    result.IsComplete = false;
                    result.Warnings.Add("Evidence file could not be hashed: " + rel.Replace('\\', '/') +
                        " (" + ex.GetType().Name + ")");
                }
                files.Add(new EvidenceFile { RelPath = rel.Replace('\\', '/'), SizeBytes = size, Sha256 = sha });
            }

            // Deterministic order so the rollup digest is stable regardless of enumeration order.
            files.Sort(delegate (EvidenceFile a, EvidenceFile b)
            {
                int insensitive = string.Compare(a.RelPath, b.RelPath, StringComparison.OrdinalIgnoreCase);
                return insensitive != 0
                    ? insensitive
                    : string.Compare(a.RelPath, b.RelPath, StringComparison.Ordinal);
            });
            result.Files.AddRange(files);
            result.Digest = ComputeRollupDigest(files);
            return result;
        }

        private static IEnumerable<string> SafeEnumerate(string root, EvidenceManifestResult result)
        {
            var files = new List<string>();
            var pending = new Stack<string>();
            pending.Push(root);
            while (pending.Count > 0)
            {
                string directory = pending.Pop();
                string[] childFiles;
                string[] childDirectories;
                try
                {
                    childFiles = Directory.GetFiles(directory, "*", SearchOption.TopDirectoryOnly);
                    childDirectories = Directory.GetDirectories(directory, "*", SearchOption.TopDirectoryOnly);
                }
                catch (Exception ex)
                {
                    MarkIncomplete(result, "Evidence directory could not be enumerated: " +
                        RelativePath(root, directory) + " (" + ex.GetType().Name + ")");
                    continue;
                }

                foreach (string file in childFiles)
                {
                    try
                    {
                        if (IsRejectedReparsePoint(File.GetAttributes(file)))
                        {
                            MarkIncomplete(result, "Evidence reparse-point file was rejected: " +
                                RelativePath(root, file));
                            continue;
                        }
                        files.Add(file);
                    }
                    catch (Exception ex)
                    {
                        MarkIncomplete(result, "Evidence file attributes could not be read: " +
                            RelativePath(root, file) + " (" + ex.GetType().Name + ")");
                    }
                }

                foreach (string child in childDirectories)
                {
                    try
                    {
                        if (IsRejectedReparsePoint(File.GetAttributes(child)))
                        {
                            MarkIncomplete(result, "Evidence reparse-point directory was rejected: " +
                                RelativePath(root, child));
                            continue;
                        }
                        pending.Push(child);
                    }
                    catch (Exception ex)
                    {
                        MarkIncomplete(result, "Evidence directory attributes could not be read: " +
                            RelativePath(root, child) + " (" + ex.GetType().Name + ")");
                    }
                }
            }
            return files;
        }

        internal static bool IsRejectedReparsePoint(FileAttributes attributes)
        {
            return (attributes & FileAttributes.ReparsePoint) != 0;
        }

        private static void MarkIncomplete(EvidenceManifestResult result, string warning)
        {
            if (result == null) return;
            result.IsComplete = false;
            if (!string.IsNullOrWhiteSpace(warning) && !result.Warnings.Contains(warning, StringComparer.OrdinalIgnoreCase))
                result.Warnings.Add(warning);
        }

        private static string RelativePath(string root, string path)
        {
            try
            {
                string rootFull = Path.GetFullPath(root).TrimEnd('\\', '/') + Path.DirectorySeparatorChar;
                string full = Path.GetFullPath(path);
                if (full.StartsWith(rootFull, StringComparison.OrdinalIgnoreCase))
                    return full.Substring(rootFull.Length).Replace('\\', '/');
                return Path.GetFileName(full);
            }
            catch
            {
                return Path.GetFileName(path) ?? "(unknown)";
            }
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
            using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
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
