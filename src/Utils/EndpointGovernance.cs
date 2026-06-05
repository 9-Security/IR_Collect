using System;
using System.Collections.Generic;

namespace IR_Collect.Utils
{
    /// <summary>Parses endpoint allowlists and tests outbound URLs (AI vs Upload lists are separate).</summary>
    public static class EndpointGovernance
    {
        /// <summary>Split allowlist: pipe-separated entries; empty lines trimmed.</summary>
        public static List<string> ParseAllowlistEntries(string raw)
        {
            var list = new List<string>();
            if (string.IsNullOrWhiteSpace(raw))
                return list;

            foreach (string part in (raw ?? "").Split(new char[] { '|' }, StringSplitOptions.None))
            {
                string t = (part ?? "").Trim();
                if (!string.IsNullOrEmpty(t))
                    list.Add(t);
            }
            return list;
        }

        /// <summary>
        /// True if <paramref name="endpoint"/> is an absolute http(s) URL that matches an allowlist entry
        /// (same scheme/host/port; path prefix with boundary rules). Empty allowlist => false.
        /// </summary>
        public static bool IsEndpointAllowed(string endpoint, string allowlistRaw)
        {
            if (string.IsNullOrWhiteSpace(endpoint))
                return false;

            Uri candidate;
            if (!Uri.TryCreate(endpoint.Trim(), UriKind.Absolute, out candidate))
                return false;

            if (!string.Equals(candidate.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(candidate.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
                return false;

            var entries = ParseAllowlistEntries(allowlistRaw);
            if (entries == null || entries.Count == 0)
                return false;

            foreach (string entry in entries)
            {
                if (string.IsNullOrWhiteSpace(entry))
                    continue;

                Uri pattern;
                if (!Uri.TryCreate(entry.Trim(), UriKind.Absolute, out pattern))
                    continue;

                if (!string.Equals(candidate.Scheme, pattern.Scheme, StringComparison.OrdinalIgnoreCase))
                    continue;

                if (!string.Equals(NormalizeHost(candidate), NormalizeHost(pattern), StringComparison.OrdinalIgnoreCase))
                    continue;

                if (candidate.Port != pattern.Port)
                    continue;

                string candPath = candidate.AbsolutePath ?? "/";
                if (string.IsNullOrEmpty(candPath)) candPath = "/";
                string patPath = pattern.AbsolutePath ?? "/";
                if (string.IsNullOrEmpty(patPath)) patPath = "/";

                if (PathPrefixMatches(candPath, patPath))
                    return true;
            }

            return false;
        }

        private static string NormalizeHost(Uri u)
        {
            if (u == null) return "";
            string h = u.Host ?? "";
            if (u.HostNameType == UriHostNameType.IPv6 && !string.IsNullOrEmpty(h) && h.Length > 2 && h[0] != '[')
                h = "[" + h + "]";
            return h;
        }

        /// <summary>HTTP path prefix match is case-sensitive (Ordinal) so allowlist entries do not broaden to differently-cased resources.</summary>
        private static bool PathPrefixMatches(string candidatePath, string patternPath)
        {
            if (string.IsNullOrEmpty(patternPath) || patternPath == "/")
                return true;

            if (string.Equals(candidatePath, patternPath, StringComparison.Ordinal))
                return true;

            if (!candidatePath.StartsWith(patternPath, StringComparison.Ordinal))
                return false;

            if (patternPath.Length > 0 && patternPath[patternPath.Length - 1] == '/')
                return true;

            if (candidatePath.Length == patternPath.Length)
                return true;

            if (candidatePath.Length < patternPath.Length)
                return false;

            char next = candidatePath[patternPath.Length];
            return next == '/' || next == '?';
        }
    }
}
