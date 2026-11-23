using System.Security.Cryptography;
using System.Text;

namespace StemPasswordGenerator.Services;

public static class SecretFingerprint
{
    public static byte[] Hash(string? value)
    {
        var bytes = Encoding.UTF8.GetBytes(value ?? string.Empty);
        try
        {
            return SHA256.HashData(bytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    public static bool Matches(string? value, byte[]? fingerprint)
    {
        if (fingerprint is not { Length: 32 })
        {
            return false;
        }

        var actual = Hash(value);
        try
        {
            return CryptographicOperations.FixedTimeEquals(actual, fingerprint);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(actual);
        }
    }
}
