using System.Runtime.InteropServices;
using System.Security.Cryptography;
using StemPasswordGenerator.Services;

namespace StemPasswordGenerator.Helpers;

internal static class PlatformKeyWrap
{
    private const string ProviderName = "Microsoft Platform Crypto Provider";
    private const string KeyName = "StemPasswordGenerator.HelloWrap.v1";
    private const int RsaBits = 2048;
    private const uint PadOaep = 0x00000004;
    private const uint SilentFlag = 0x00000040;
    private const int NteBadKeyset = unchecked((int)0x80090016);
    private const int NteExists = unchecked((int)0x8009000F);

    public static bool TryProtect(byte[] plaintext, out byte[] blob)
    {
        blob = [];
        ArgumentNullException.ThrowIfNull(plaintext);
        var ciphertext = Encrypt(plaintext);
        if (ciphertext is null)
        {
            return false;
        }

        try
        {
            blob = PlatformWrapBlob.Pack(ciphertext);
            return true;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ciphertext);
        }
    }

    public static bool TryUnprotect(byte[] blob, out byte[] plaintext)
    {
        plaintext = [];
        ArgumentNullException.ThrowIfNull(blob);
        if (!PlatformWrapBlob.LooksLike(blob))
        {
            return false;
        }

        byte[]? ciphertext = null;
        try
        {
            ciphertext = PlatformWrapBlob.Unpack(blob);
            var opened = Decrypt(ciphertext);
            if (opened is null)
            {
                return false;
            }

            plaintext = opened;
            return true;
        }
        catch (CryptographicException)
        {
            return false;
        }
        finally
        {
            if (ciphertext is not null)
            {
                CryptographicOperations.ZeroMemory(ciphertext);
            }
        }
    }

    private static byte[]? Encrypt(byte[] plaintext)
    {
        if (NCryptOpenStorageProvider(out var provider, ProviderName, 0) != 0)
        {
            return null;
        }

        try
        {
            var key = OpenOrCreateKey(provider);
            if (key == nint.Zero)
            {
                return null;
            }

            try
            {
                var size = 0;
                if (NCryptEncrypt(key, plaintext, plaintext.Length, nint.Zero, null, 0, ref size, PadOaep) != 0 || size <= 0)
                {
                    return null;
                }

                var output = new byte[size];
                return NCryptEncrypt(key, plaintext, plaintext.Length, nint.Zero, output, output.Length, ref size, PadOaep) == 0
                    ? output
                    : null;
            }
            finally
            {
                _ = NCryptFreeObject(key);
            }
        }
        finally
        {
            _ = NCryptFreeObject(provider);
        }
    }

    private static byte[]? Decrypt(byte[] ciphertext)
    {
        if (NCryptOpenStorageProvider(out var provider, ProviderName, 0) != 0)
        {
            return null;
        }

        try
        {
            var status = NCryptOpenKey(provider, out var key, KeyName, 0, 0);
            if (status != 0 || key == nint.Zero)
            {
                return null;
            }

            try
            {
                var size = 0;
                if (NCryptDecrypt(key, ciphertext, ciphertext.Length, nint.Zero, null, 0, ref size, PadOaep) != 0 || size <= 0)
                {
                    return null;
                }

                var output = new byte[size];
                return NCryptDecrypt(key, ciphertext, ciphertext.Length, nint.Zero, output, output.Length, ref size, PadOaep) == 0
                    ? output
                    : null;
            }
            finally
            {
                _ = NCryptFreeObject(key);
            }
        }
        finally
        {
            _ = NCryptFreeObject(provider);
        }
    }

    private static nint OpenOrCreateKey(nint provider)
    {
        var status = NCryptOpenKey(provider, out var key, KeyName, 0, 0);
        if (status == 0 && key != nint.Zero)
        {
            return key;
        }

        status = NCryptCreatePersistedKey(provider, out key, "RSA", KeyName, 0, 0);
        if (status == NteExists)
        {
            return NCryptOpenKey(provider, out key, KeyName, 0, 0) == 0 ? key : nint.Zero;
        }

        if (status != 0)
        {
            return nint.Zero;
        }

        var bits = RsaBits;
        if (NCryptSetProperty(key, "Length", ref bits, sizeof(int), SilentFlag) != 0)
        {
            _ = NCryptFreeObject(key);
            return nint.Zero;
        }

        var policy = new UiPolicy
        {
            Version = 1,
            Flags = 0x2,
            CreationTitle = "Stem Password Generator",
            FriendlyName = "Stem vault unlock",
            Description = "Unlock the Stem vault key"
        };
        _ = NCryptSetProperty(key, "UI Policy", ref policy, Marshal.SizeOf<UiPolicy>(), 0);

        if (NCryptFinalizeKey(key, 0) != 0)
        {
            _ = NCryptFreeObject(key);
            return nint.Zero;
        }

        return key;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct UiPolicy
    {
        public uint Version;
        public uint Flags;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string CreationTitle;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string FriendlyName;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string Description;
    }

    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int NCryptOpenStorageProvider(out nint provider, string providerName, uint flags);

    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int NCryptOpenKey(nint provider, out nint key, string keyName, uint spec, uint flags);

    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int NCryptCreatePersistedKey(nint provider, out nint key, string algorithm, string keyName, uint spec, uint flags);

    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int NCryptSetProperty(nint key, string name, ref int value, int length, uint flags);

    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int NCryptSetProperty(nint key, string name, ref UiPolicy value, int length, uint flags);

    [DllImport("ncrypt.dll")]
    private static extern int NCryptFinalizeKey(nint key, uint flags);

    [DllImport("ncrypt.dll")]
    private static extern int NCryptEncrypt(nint key, byte[] input, int inputLength, nint paddingInfo, byte[]? output, int outputLength, ref int resultLength, uint flags);

    [DllImport("ncrypt.dll")]
    private static extern int NCryptDecrypt(nint key, byte[] input, int inputLength, nint paddingInfo, byte[]? output, int outputLength, ref int resultLength, uint flags);

    [DllImport("ncrypt.dll")]
    private static extern int NCryptFreeObject(nint handle);
}
