using System;
using System.Collections.Generic;
using System.Net;

namespace IR_Collect.Utils
{
    /// <summary>Forces modern TLS for outbound HTTP(S) and excludes legacy SSL3/Tls/Tls11 when possible.</summary>
    public static class OutboundTlsHelper
    {
        private static bool _configured;
        private static readonly object _gate = new object();

        public static void EnsureModernTlsForOutboundRequests()
        {
            lock (_gate)
            {
                if (_configured) return;
                if (!TryApplyProtocolFlags())
                {
                    throw new InvalidOperationException(
                        "Could not configure TLS 1.2 (or newer) for outbound HTTP(S). Refusing to send over legacy SSL/TLS.");
                }
                _configured = true;
            }
        }

        internal static SecurityProtocolType ComputePreferredProtocols()
        {
            SecurityProtocolType protocols = SecurityProtocolType.Tls12;
            const SecurityProtocolType tls13 = (SecurityProtocolType)12288;
            try
            {
                ServicePointManager.SecurityProtocol = protocols | tls13;
                protocols = protocols | tls13;
            }
            catch
            {
                // TLS 1.3 enum not defined on older .NET; Tls12 alone is sufficient.
            }
            return protocols;
        }

        /// <summary>True when the flag set includes modern TLS and excludes SSL3/Tls/Tls11.</summary>
        internal static bool ProtocolSelectionIsAcceptable(SecurityProtocolType sp)
        {
            if ((sp & SecurityProtocolType.Tls12) == 0 && (sp & (SecurityProtocolType)12288) == 0)
                return false;
            if ((sp & SecurityProtocolType.Ssl3) != 0) return false;
            if ((sp & SecurityProtocolType.Tls) != 0) return false;
            if ((sp & (SecurityProtocolType)768) != 0) return false;
            return true;
        }

        private static bool TryApplyProtocolFlags()
        {
            SecurityProtocolType protocols = ComputePreferredProtocols();
            try
            {
                ServicePointManager.SecurityProtocol = protocols;
            }
            catch
            {
                try { ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12; }
                catch { return false; }
            }
            return ProtocolSelectionIsAcceptable(ServicePointManager.SecurityProtocol);
        }

        /// <summary>Test hook: returns enabled protocol flag names (uppercase) after configuration.</summary>
        internal static IList<string> GetEnabledProtocolNamesForTest()
        {
            EnsureModernTlsForOutboundRequests();
            var names = new List<string>();
            SecurityProtocolType sp = ServicePointManager.SecurityProtocol;
            if ((sp & SecurityProtocolType.Ssl3) != 0) names.Add("Ssl3");
            if ((sp & SecurityProtocolType.Tls) != 0) names.Add("Tls");
            if ((sp & (SecurityProtocolType)768) != 0) names.Add("Tls11");
            if ((sp & SecurityProtocolType.Tls12) != 0) names.Add("Tls12");
            if ((sp & (SecurityProtocolType)12288) != 0) names.Add("Tls13");
            return names;
        }
    }
}
