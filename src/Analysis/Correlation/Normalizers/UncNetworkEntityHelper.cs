using System;
using System.Net;
using System.Net.Sockets;
using IR_Collect;

namespace IR_Collect.Analysis.Correlation.Normalizers
{
    /// <summary>
    /// Facts-only extraction of Workstation / ShareName / RemoteIP from UNC paths or http(s) URLs.
    /// Does not interpret intent; supports cross-source pivot with Event Log and other artifacts.
    /// </summary>
    public static class UncNetworkEntityHelper
    {
        /// <summary>Add derived entities when <paramref name="remoteOrPath"/> looks like a UNC path or absolute http(s) URL.</summary>
        public static void AddFromUncOrUrl(Fact fact, string remoteOrPath)
        {
            if (fact == null || string.IsNullOrWhiteSpace(remoteOrPath))
                return;

            string s = remoteOrPath.Trim();
            if (s.StartsWith("\\\\", StringComparison.Ordinal))
            {
                AddFromUnc(fact, s);
                return;
            }

            if (s.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                s.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                TryAddFromHttp(fact, s);
            }
        }

        private static void AddFromUnc(Fact fact, string unc)
        {
            // \\server\share[\path...]
            string rest = unc.Length >= 2 ? unc.Substring(2) : "";
            if (string.IsNullOrEmpty(rest))
                return;

            int sep = rest.IndexOf('\\');
            string server = sep >= 0 ? rest.Substring(0, sep) : rest;
            string afterServer = sep >= 0 && sep + 1 < rest.Length ? rest.Substring(sep + 1) : "";

            if (string.IsNullOrEmpty(server))
                return;

            string ipNorm;
            if (TryNormalizeIPv4(server, out ipNorm))
                fact.AddEntity("RemoteIP", ipNorm);
            else
                fact.AddEntity("Workstation", server);

            if (string.IsNullOrEmpty(afterServer))
                return;

            int shareEnd = afterServer.IndexOf('\\');
            string share = shareEnd >= 0 ? afterServer.Substring(0, shareEnd) : afterServer;
            if (!string.IsNullOrEmpty(share))
                fact.AddEntity("ShareName", share);
        }

        private static void TryAddFromHttp(Fact fact, string url)
        {
            try
            {
                var uri = new Uri(url);
                string host = uri.Host;
                if (string.IsNullOrEmpty(host))
                    return;

                string ipNorm;
                if (TryNormalizeIPv4(host, out ipNorm))
                    fact.AddEntity("RemoteIP", ipNorm);
            }
            catch
            {
                // ignore malformed URLs — still keep full string on the fact elsewhere
            }
        }

        private static bool TryNormalizeIPv4(string host, out string normalized)
        {
            normalized = null;
            if (string.IsNullOrWhiteSpace(host))
                return false;

            IPAddress addr;
            if (!IPAddress.TryParse(host.Trim(), out addr))
                return false;

            if (addr.AddressFamily != AddressFamily.InterNetwork)
                return false;

            normalized = addr.ToString();
            return true;
        }
    }
}
