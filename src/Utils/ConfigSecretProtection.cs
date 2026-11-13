using System;
using System.Security.Cryptography;
using System.Text;

namespace IR_Collect.Utils
{
    /// <summary>DPAPI protection for API keys stored in config.ini (CurrentUser scope).</summary>
    internal static class ConfigSecretProtection
    {
        internal const string DpapiPrefix = "dpapi:";
        internal const string UiDecryptFailedPlaceholder = "(stored key cannot be decrypted on this user/machine — enter a new key or use Clear)";
        private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("IR_Collect.ConfigSecret.v1");

        internal static readonly string[] ProtectedSettingKeys = new string[]
        {
            "AiApiKey",
            "UploadApiKey"
        };

        internal static string ProtectForStorage(string plaintext)
        {
            if (plaintext == null) plaintext = "";
            if (plaintext.Length == 0) return "";
            byte[] data = Encoding.UTF8.GetBytes(plaintext);
            byte[] protectedBytes = ProtectedData.Protect(data, Entropy, DataProtectionScope.CurrentUser);
            return DpapiPrefix + Convert.ToBase64String(protectedBytes);
        }

        internal static string UnprotectForUse(string stored, string settingKey)
        {
            bool failed;
            return UnprotectForUse(stored, settingKey, out failed);
        }

        internal static string UnprotectForUse(string stored, string settingKey, out bool decryptionFailed)
        {
            decryptionFailed = false;
            if (string.IsNullOrEmpty(stored)) return "";
            if (!stored.StartsWith(DpapiPrefix, StringComparison.Ordinal))
                return stored;
            string b64 = stored.Substring(DpapiPrefix.Length);
            try
            {
                byte[] cipher = Convert.FromBase64String(b64);
                byte[] plain = ProtectedData.Unprotect(cipher, Entropy, DataProtectionScope.CurrentUser);
                return Encoding.UTF8.GetString(plain);
            }
            catch (Exception ex)
            {
                decryptionFailed = true;
                Logger.Warning("Config: could not decrypt " + (settingKey ?? "secret") +
                    " (wrong user or machine). Re-enter the key in Advanced → Settings. " + (ex.Message ?? ""));
                return "";
            }
        }

        internal static bool IsProtectedKey(string key)
        {
            if (string.IsNullOrEmpty(key)) return false;
            foreach (string k in ProtectedSettingKeys)
            {
                if (string.Equals(k, key, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }

        /// <summary>Resolve value to persist after Settings UI edit (preserve ciphertext when unchanged after decrypt failure).</summary>
        internal static string ResolveSecretForSave(string storedCiphertext, string uiText, bool userRequestedClear, bool uiShowsDecryptFailure)
        {
            string text = uiText ?? "";
            if (userRequestedClear)
            {
                if (string.IsNullOrEmpty(text) || string.Equals(text, UiDecryptFailedPlaceholder, StringComparison.Ordinal))
                    return "";
                return text.Trim();
            }
            if (uiShowsDecryptFailure)
            {
                if (string.IsNullOrEmpty(text) || string.Equals(text, UiDecryptFailedPlaceholder, StringComparison.Ordinal))
                    return storedCiphertext ?? "";
                return text.Trim();
            }
            return text.Trim();
        }
    }
}
