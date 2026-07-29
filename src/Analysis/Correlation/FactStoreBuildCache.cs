using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Security.Cryptography;
using System.Text;
using IR_Collect.Utils;

namespace IR_Collect.Analysis.Correlation
{
    [DataContract]
    public sealed class FactStoreInputFingerprint
    {
        [DataMember(Name = "relative_path")] public string RelativePath { get; set; }
        [DataMember(Name = "size")] public long Size { get; set; }
        [DataMember(Name = "mtime_utc")] public string MtimeUtc { get; set; }
        [DataMember(Name = "sha256")] public string Sha256 { get; set; }
        [DataMember(Name = "normalizer_name")] public string NormalizerName { get; set; }

        public string FullPath { get; set; }
    }

    [DataContract]
    internal sealed class FactStoreBuildCacheEnvelope
    {
        [DataMember(Name = "cache_schema")] public string CacheSchema { get; set; }
        [DataMember(Name = "tool_version")] public string ToolVersion { get; set; }
        [DataMember(Name = "generated_at")] public string GeneratedAt { get; set; }
        [DataMember(Name = "source_identity")] public string SourceIdentity { get; set; }
        [DataMember(Name = "evidence_digest")] public string EvidenceDigest { get; set; }
        [DataMember(Name = "config_fingerprint")] public string ConfigFingerprint { get; set; }
        [DataMember(Name = "inputs")] public List<FactStoreInputFingerprint> Inputs { get; set; }
        [DataMember(Name = "facts")] public List<Fact> Facts { get; set; }

        public FactStoreBuildCacheEnvelope()
        {
            Inputs = new List<FactStoreInputFingerprint>();
            Facts = new List<Fact>();
        }
    }

    public sealed class FactStoreBuildResult
    {
        public FactStore Store { get; set; }
        public string BuildMode { get; set; }
        public string GeneratedAt { get; set; }
        public string Detail { get; set; }
        public string CachePath { get; set; }
        public bool CacheWritten { get; set; }
        public List<string> RebuiltGroups { get; private set; }
        public List<string> ReusedGroups { get; private set; }
        public List<FactStoreInputFingerprint> Inputs { get; set; }

        public FactStoreBuildResult()
        {
            BuildMode = "Full";
            GeneratedAt = DateTime.UtcNow.ToString("o");
            Detail = "";
            CachePath = "";
            RebuiltGroups = new List<string>();
            ReusedGroups = new List<string>();
            Inputs = new List<FactStoreInputFingerprint>();
        }
    }

    /// <summary>
    /// Persistent, facts-only build cache. Exact input matches reuse all normalized facts. When only
    /// filtered Event Log CSV inputs changed, cached non-EventLog facts are retained and only affected
    /// EventLog normalizers run. Other changes fail safe to the established full builder.
    /// </summary>
    public static class FactStoreBuildCoordinator
    {
        public const string CacheSchema = "fact_store_build_cache_v1";
        private const string CacheFileName = "fact_store_build_cache_v1.json.gz";
        private const long MaxCompressedCacheBytes = 1024L * 1024L * 1024L;
        private const long MaxDecompressedCacheBytes = 4L * 1024L * 1024L * 1024L;

        public static FactStoreBuildResult Build(CaseData c, bool allowReuse, bool persistCache)
        {
            return Build(c, allowReuse, persistCache, null);
        }

        public static FactStoreBuildResult BuildConfigured(CaseData c)
        {
            bool enabled = new ConfigManager().Get("FactStoreIncrementalCache") == "1";
            return Build(c, enabled, enabled, null);
        }

        internal static FactStoreBuildResult Build(CaseData c, bool allowReuse, bool persistCache, string cacheRootOverride)
        {
            if (c == null) throw new ArgumentNullException("c");

            var result = new FactStoreBuildResult();
            result.Inputs = BuildInputManifest(c);
            string sourceIdentity = ResolveSourceIdentity(c);
            string configFingerprint = BuildConfigFingerprint();
            string cachePath = ResolveCachePath(sourceIdentity, cacheRootOverride);
            result.CachePath = cachePath;

            FactStoreBuildCacheEnvelope cached = null;
            string fallbackReason = "";
            if (allowReuse && !string.IsNullOrEmpty(cachePath) && File.Exists(cachePath))
            {
                try
                {
                    cached = Load(cachePath);
                    fallbackReason = ValidateEnvelope(cached, sourceIdentity, configFingerprint);
                    if (!string.IsNullOrEmpty(fallbackReason)) cached = null;
                }
                catch (Exception ex)
                {
                    fallbackReason = "Persistent cache could not be read: " + ex.Message;
                    Logger.Warning("FactStore build cache load: " + ex.Message);
                }
            }
            else if (allowReuse)
            {
                fallbackReason = "No persistent cache was available for this evidence source.";
            }
            else
            {
                fallbackReason = "Full rebuild was requested.";
            }

            if (cached != null)
            {
                List<FactStoreInputFingerprint> changed = FindChangedInputs(cached.Inputs, result.Inputs);
                if (changed.Count == 0)
                {
                    result.Store = FactStore.CreateFromFacts(c, cached.Facts);
                    result.BuildMode = "Reused";
                    result.GeneratedAt = cached.GeneratedAt ?? result.GeneratedAt;
                    result.ReusedGroups.Add("All");
                    result.Detail = "All normalized input fingerprints matched the persistent cache.";
                    ApplyResult(c, result);
                    return result;
                }

                if (changed.All(IsEventLogInput))
                {
                    result.Store = BuildEventLogIncremental(c, cached.Facts, changed, result);
                    result.BuildMode = "Incremental";
                    result.Detail = "Only changed filtered Event Log inputs were normalized; unchanged facts were reused.";
                }
                else
                {
                    fallbackReason = "Changed inputs require a full rebuild: " + FormatInputSample(changed) + ".";
                }
            }

            if (result.Store == null)
            {
                result.Store = FactStore.BuildFromCase(c);
                result.BuildMode = "Full";
                result.RebuiltGroups.Add("All");
                result.Detail = fallbackReason;
            }

            if (persistCache && result.Store != null)
            {
                try
                {
                    Save(cachePath, new FactStoreBuildCacheEnvelope
                    {
                        CacheSchema = CacheSchema,
                        ToolVersion = BuildInfo.Version,
                        GeneratedAt = result.GeneratedAt,
                        SourceIdentity = sourceIdentity,
                        EvidenceDigest = c.EvidenceDigest ?? "",
                        ConfigFingerprint = configFingerprint,
                        Inputs = CloneInputs(result.Inputs),
                        Facts = result.Store.Facts != null ? new List<Fact>(result.Store.Facts) : new List<Fact>()
                    });
                    result.CacheWritten = true;
                }
                catch (Exception ex)
                {
                    result.Detail = AppendDetail(result.Detail, "Persistent cache write failed: " + ex.Message);
                    Logger.Warning("FactStore build cache save: " + ex.Message);
                }
            }

            ApplyResult(c, result);
            return result;
        }

        public static int ClearPersistentCache()
        {
            string root = GetDefaultCacheRoot();
            if (string.IsNullOrEmpty(root) || !Directory.Exists(root)) return 0;
            int files = 0;
            foreach (string file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
                files++;
            Directory.Delete(root, true);
            return files;
        }

        internal static List<FactStoreInputFingerprint> BuildInputManifest(CaseData c)
        {
            var records = new Dictionary<string, FactStoreInputFingerprint>(StringComparer.OrdinalIgnoreCase);
            foreach (string path in CaseManager.EnumerateFactStoreSourcePaths(c, null, null))
            {
                AddInput(c, records, path, ResolveNormalizerName(path));
            }
            foreach (var kvp in FactStore.GetEventLogFilteredCsvPaths(c))
            {
                AddInput(c, records, kvp.Value, Normalizers.EventLogNormalizer.SourcePrefix + ":" + kvp.Key);
            }
            return records.Values
                .OrderBy(x => x.RelativePath ?? "", StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        private static FactStore BuildEventLogIncremental(
            CaseData c,
            List<Fact> cachedFacts,
            List<FactStoreInputFingerprint> changed,
            FactStoreBuildResult result)
        {
            var labels = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (FactStoreInputFingerprint input in changed)
            {
                string label = GetEventLogLabel(input.NormalizerName);
                if (!string.IsNullOrEmpty(label)) labels.Add(label);
            }

            var facts = (cachedFacts ?? new List<Fact>())
                .Where(f => f == null || !labels.Contains(GetEventLogLabel(f.Source)))
                .ToList();
            foreach (var kvp in FactStore.GetEventLogFilteredCsvPaths(c))
            {
                if (!labels.Contains(kvp.Key)) continue;
                facts.AddRange(Normalizers.EventLogNormalizer.ToFacts(kvp.Value, kvp.Key));
                result.RebuiltGroups.Add(Normalizers.EventLogNormalizer.SourcePrefix + ":" + kvp.Key);
            }

            result.ReusedGroups.Add("Non-EventLog");
            return FactStore.CreateFromFacts(c, facts);
        }

        private static void AddInput(
            CaseData c,
            Dictionary<string, FactStoreInputFingerprint> records,
            string path,
            string normalizerName)
        {
            if (string.IsNullOrEmpty(path) || !File.Exists(path)) return;
            string relative = GetStableRelativePath(c, path);
            string key = relative + "|" + (normalizerName ?? "");
            if (records.ContainsKey(key)) return;

            var info = new FileInfo(path);
            string sha = FindEvidenceSha256(c, path);
            if (string.IsNullOrEmpty(sha))
                sha = EvidenceManifest.ComputeSha256(path);
            records[key] = new FactStoreInputFingerprint
            {
                RelativePath = relative,
                Size = info.Length,
                MtimeUtc = info.LastWriteTimeUtc.ToString("o"),
                Sha256 = sha ?? "",
                NormalizerName = normalizerName ?? "",
                FullPath = path
            };
        }

        private static string FindEvidenceSha256(CaseData c, string path)
        {
            if (c == null || c.EvidenceFiles == null || string.IsNullOrEmpty(c.EvidencePath))
                return "";
            string relative = RelativeUnder(c.EvidencePath, path);
            if (string.IsNullOrEmpty(relative)) return "";
            EvidenceFile match = c.EvidenceFiles.FirstOrDefault(x =>
                x != null && string.Equals(
                    (x.RelPath ?? "").Replace('\\', '/'),
                    relative.Replace('\\', '/'),
                    StringComparison.OrdinalIgnoreCase));
            return match != null ? (match.Sha256 ?? "") : "";
        }

        private static string ResolveNormalizerName(string path)
        {
            string name = Path.GetFileName(path) ?? "";
            if (ArtifactNames.IsEventLogFilteredCsv(name))
                return Normalizers.EventLogNormalizer.SourcePrefix + ":" + ArtifactNames.GetEventLogLabelFromFileName(name);
            if (name.EndsWith(".pf", StringComparison.OrdinalIgnoreCase))
                return "Prefetch";
            return name;
        }

        private static string GetStableRelativePath(CaseData c, string path)
        {
            string relative = c != null ? RelativeUnder(c.AnalysisPath, path) : "";
            if (!string.IsNullOrEmpty(relative)) return "analysis/" + relative.Replace('\\', '/');
            relative = c != null ? RelativeUnder(c.EvidencePath, path) : "";
            if (!string.IsNullOrEmpty(relative)) return "evidence/" + relative.Replace('\\', '/');
            return "external/" + (Path.GetFileName(path) ?? "");
        }

        private static string RelativeUnder(string root, string path)
        {
            if (string.IsNullOrEmpty(root) || string.IsNullOrEmpty(path)) return "";
            string rootFull = Path.GetFullPath(root).TrimEnd('\\', '/') + Path.DirectorySeparatorChar;
            string pathFull = Path.GetFullPath(path);
            if (!pathFull.StartsWith(rootFull, StringComparison.OrdinalIgnoreCase)) return "";
            return pathFull.Substring(rootFull.Length);
        }

        private static List<FactStoreInputFingerprint> FindChangedInputs(
            List<FactStoreInputFingerprint> before,
            List<FactStoreInputFingerprint> after)
        {
            Dictionary<string, FactStoreInputFingerprint> oldMap = BuildInputMap(before);
            Dictionary<string, FactStoreInputFingerprint> newMap = BuildInputMap(after);
            var keys = new HashSet<string>(oldMap.Keys, StringComparer.OrdinalIgnoreCase);
            keys.UnionWith(newMap.Keys);
            var changed = new List<FactStoreInputFingerprint>();
            foreach (string key in keys)
            {
                FactStoreInputFingerprint oldValue;
                FactStoreInputFingerprint newValue;
                oldMap.TryGetValue(key, out oldValue);
                newMap.TryGetValue(key, out newValue);
                if (oldValue == null || newValue == null || !FingerprintEquals(oldValue, newValue))
                    changed.Add(newValue ?? oldValue);
            }
            return changed;
        }

        private static Dictionary<string, FactStoreInputFingerprint> BuildInputMap(
            IEnumerable<FactStoreInputFingerprint> inputs)
        {
            var map = new Dictionary<string, FactStoreInputFingerprint>(StringComparer.OrdinalIgnoreCase);
            foreach (FactStoreInputFingerprint input in inputs ?? Enumerable.Empty<FactStoreInputFingerprint>())
            {
                if (input == null) continue;
                map[InputKey(input)] = input;
            }
            return map;
        }

        private static bool FingerprintEquals(FactStoreInputFingerprint x, FactStoreInputFingerprint y)
        {
            if (x == null || y == null) return false;
            if (!string.Equals(x.RelativePath, y.RelativePath, StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(x.NormalizerName, y.NormalizerName, StringComparison.OrdinalIgnoreCase) ||
                x.Size != y.Size)
                return false;
            if (!string.IsNullOrEmpty(x.Sha256) && !string.IsNullOrEmpty(y.Sha256))
                return string.Equals(x.Sha256, y.Sha256, StringComparison.OrdinalIgnoreCase);
            return string.Equals(x.MtimeUtc, y.MtimeUtc, StringComparison.Ordinal);
        }

        private static string InputKey(FactStoreInputFingerprint x)
        {
            return (x.RelativePath ?? "") + "|" + (x.NormalizerName ?? "");
        }

        private static bool IsEventLogInput(FactStoreInputFingerprint input)
        {
            return input != null &&
                !string.IsNullOrEmpty(GetEventLogLabel(input.NormalizerName));
        }

        private static string GetEventLogLabel(string source)
        {
            string prefix = Normalizers.EventLogNormalizer.SourcePrefix + ":";
            if (string.IsNullOrEmpty(source) || !source.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                return "";
            return source.Substring(prefix.Length);
        }

        private static string ResolveSourceIdentity(CaseData c)
        {
            string source = !string.IsNullOrWhiteSpace(c.SourceZip)
                ? c.SourceZip
                : (!string.IsNullOrWhiteSpace(c.EvidencePath) ? c.EvidencePath : c.ExtractPath);
            try { source = Path.GetFullPath(source ?? ""); } catch { source = source ?? ""; }
            return source.Trim().ToLowerInvariant();
        }

        private static string BuildConfigFingerprint()
        {
            var cfg = new ConfigManager();
            string value = "tool=" + BuildInfo.Version +
                "|mft=" + cfg.Get("MftMaxEntries") +
                "|event_days=" + cfg.Get("EventLogDays") +
                "|event_max=" + cfg.Get("EventLogMaxEvents");
            return HashText(value);
        }

        private static string ValidateEnvelope(
            FactStoreBuildCacheEnvelope envelope,
            string sourceIdentity,
            string configFingerprint)
        {
            if (envelope == null) return "Persistent cache is empty.";
            if (!string.Equals(envelope.CacheSchema, CacheSchema, StringComparison.Ordinal))
                return "Persistent cache schema is incompatible.";
            if (!string.Equals(envelope.ToolVersion, BuildInfo.Version, StringComparison.Ordinal))
                return "Persistent cache was produced by a different tool version.";
            if (!string.Equals(envelope.SourceIdentity, sourceIdentity, StringComparison.OrdinalIgnoreCase))
                return "Persistent cache belongs to a different evidence source.";
            if (!string.Equals(envelope.ConfigFingerprint, configFingerprint, StringComparison.Ordinal))
                return "Fact Store input settings changed.";
            if (envelope.Facts == null || envelope.Inputs == null)
                return "Persistent cache is incomplete.";
            return "";
        }

        private static string ResolveCachePath(string sourceIdentity, string rootOverride)
        {
            string root = string.IsNullOrEmpty(rootOverride) ? GetDefaultCacheRoot() : rootOverride;
            if (string.IsNullOrEmpty(root)) return "";
            string key = HashText(sourceIdentity ?? "").Substring(0, 32);
            return Path.Combine(root, key, CacheFileName);
        }

        private static string GetDefaultCacheRoot()
        {
            string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            if (string.IsNullOrEmpty(local)) return "";
            return Path.Combine(local, BuildInfo.ToolName, "FactStoreCache");
        }

        private static string HashText(string value)
        {
            using (SHA256 sha = SHA256.Create())
            {
                byte[] hash = sha.ComputeHash(Encoding.UTF8.GetBytes(value ?? ""));
                var sb = new StringBuilder(hash.Length * 2);
                foreach (byte b in hash) sb.Append(b.ToString("x2"));
                return sb.ToString();
            }
        }

        private static FactStoreBuildCacheEnvelope Load(string path)
        {
            var info = new FileInfo(path);
            if (info.Length > MaxCompressedCacheBytes)
                throw new InvalidDataException("Persistent cache exceeds the 1 GiB compressed safety limit.");

            var serializer = CreateCacheSerializer();
            using (FileStream file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (GZipStream gzip = new GZipStream(file, CompressionMode.Decompress))
            using (var bounded = new BoundedReadStream(gzip, MaxDecompressedCacheBytes))
                return serializer.ReadObject(bounded) as FactStoreBuildCacheEnvelope;
        }

        private static void Save(string path, FactStoreBuildCacheEnvelope envelope)
        {
            if (string.IsNullOrEmpty(path)) throw new InvalidOperationException("Fact Store cache path is unavailable.");
            string dir = Path.GetDirectoryName(path);
            if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);
            string temp = AtomicFile.CreateTempPath(path);
            try
            {
                var serializer = CreateCacheSerializer();
                using (FileStream file = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None))
                using (GZipStream gzip = new GZipStream(file, CompressionMode.Compress))
                    serializer.WriteObject(gzip, envelope);
                AtomicFile.Commit(temp, path);
                temp = null;
                ConfigManager.TryRestrictAclToCurrentUser(path);
            }
            finally
            {
                AtomicFile.TryDelete(temp);
            }
        }

        private static DataContractJsonSerializer CreateCacheSerializer()
        {
            return new DataContractJsonSerializer(
                typeof(FactStoreBuildCacheEnvelope),
                new DataContractJsonSerializerSettings
                {
                    MaxItemsInObjectGraph = int.MaxValue,
                    UseSimpleDictionaryFormat = true
                });
        }

        private static List<FactStoreInputFingerprint> CloneInputs(IEnumerable<FactStoreInputFingerprint> source)
        {
            return (source ?? Enumerable.Empty<FactStoreInputFingerprint>()).Select(x =>
                new FactStoreInputFingerprint
                {
                    RelativePath = x.RelativePath ?? "",
                    Size = x.Size,
                    MtimeUtc = x.MtimeUtc ?? "",
                    Sha256 = x.Sha256 ?? "",
                    NormalizerName = x.NormalizerName ?? ""
                }).ToList();
        }

        private static void ApplyResult(CaseData c, FactStoreBuildResult result)
        {
            c.FactStoreBuildMode = result.BuildMode ?? "";
            c.FactStoreBuildGeneratedAt = result.GeneratedAt ?? "";
            c.FactStoreBuildDetail = result.Detail ?? "";
            c.FactStoreBuildInputs = CloneInputs(result.Inputs);
        }

        private static string FormatInputSample(IEnumerable<FactStoreInputFingerprint> inputs)
        {
            List<string> names = (inputs ?? Enumerable.Empty<FactStoreInputFingerprint>())
                .Where(x => x != null)
                .Select(x => x.RelativePath ?? x.NormalizerName ?? "(unknown)")
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(4)
                .ToList();
            return names.Count == 0 ? "(unknown)" : string.Join(", ", names.ToArray());
        }

        private static string AppendDetail(string existing, string value)
        {
            if (string.IsNullOrWhiteSpace(existing)) return value ?? "";
            if (string.IsNullOrWhiteSpace(value)) return existing;
            return existing.TrimEnd() + " " + value.Trim();
        }

        private sealed class BoundedReadStream : Stream
        {
            private readonly Stream _inner;
            private readonly long _maximumBytes;
            private long _bytesRead;

            public BoundedReadStream(Stream inner, long maximumBytes)
            {
                if (inner == null) throw new ArgumentNullException("inner");
                if (maximumBytes <= 0) throw new ArgumentOutOfRangeException("maximumBytes");
                _inner = inner;
                _maximumBytes = maximumBytes;
            }

            public override bool CanRead { get { return true; } }
            public override bool CanSeek { get { return false; } }
            public override bool CanWrite { get { return false; } }
            public override long Length { get { throw new NotSupportedException(); } }
            public override long Position
            {
                get { return _bytesRead; }
                set { throw new NotSupportedException(); }
            }

            public override int Read(byte[] buffer, int offset, int count)
            {
                if (_bytesRead >= _maximumBytes)
                {
                    int extra = _inner.Read(buffer, offset, Math.Min(count, 1));
                    if (extra > 0)
                        throw new InvalidDataException("Persistent cache exceeds the 4 GiB decompressed safety limit.");
                    return 0;
                }

                int allowed = (int)Math.Min((long)count, _maximumBytes - _bytesRead);
                int read = _inner.Read(buffer, offset, allowed);
                _bytesRead += read;
                return read;
            }

            public override void Flush() { }
            public override long Seek(long offset, SeekOrigin origin) { throw new NotSupportedException(); }
            public override void SetLength(long value) { throw new NotSupportedException(); }
            public override void Write(byte[] buffer, int offset, int count) { throw new NotSupportedException(); }
        }
    }
}
