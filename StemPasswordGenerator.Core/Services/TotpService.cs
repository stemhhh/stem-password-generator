using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace StemPasswordGenerator.Services;

public static class TotpService
{
    public const int PeriodSeconds = 30;
    public const int Digits = 6;

    public static string GenerateSecret()
    {
        return Base32Encoding.Encode(RandomNumberGenerator.GetBytes(20));
    }

    public static int SecondsRemaining(DateTimeOffset? utc = null)
    {
        var seconds = (utc ?? DateTimeOffset.UtcNow).ToUnixTimeSeconds();
        return PeriodSeconds - (int)(seconds % PeriodSeconds);
    }

    public static string GetCode(string secret, DateTimeOffset? utc = null)
    {
        var key = Base32Encoding.Decode(secret);
        try
        {
            return GetCode(key, (utc ?? DateTimeOffset.UtcNow).ToUnixTimeSeconds());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    public static string GetCode(byte[] key, long unixSeconds)
    {
        ArgumentNullException.ThrowIfNull(key);
        var counter = (ulong)(unixSeconds / PeriodSeconds);
        Span<byte> counterBytes = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(counterBytes, counter);
        Span<byte> hash = stackalloc byte[20];
        using var hmac = new HMACSHA1(key);
        if (!hmac.TryComputeHash(counterBytes, hash, out _))
        {
            throw new CryptographicException("Could not compute the authenticator code.");
        }

        var offset = hash[^1] & 0x0F;
        var binary =
            ((hash[offset] & 0x7F) << 24)
            | (hash[offset + 1] << 16)
            | (hash[offset + 2] << 8)
            | hash[offset + 3];
        return (binary % 1_000_000).ToString("D6");
    }

    public static bool TryGetCode(string? secret, out string code)
    {
        code = string.Empty;
        if (!TryDecode(secret, out var key))
        {
            return false;
        }

        try
        {
            code = GetCode(key, DateTimeOffset.UtcNow.ToUnixTimeSeconds());
            return true;
        }
        catch (Exception)
        {
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    public static bool TryDecode(string? secret, out byte[] key)
    {
        key = [];
        if (string.IsNullOrWhiteSpace(secret))
        {
            return false;
        }

        try
        {
            key = Base32Encoding.Decode(secret);
            return key.Length > 0;
        }
        catch (Exception)
        {
            key = [];
            return false;
        }
    }

    public static string? TryParseOtpAuth(string uri)
    {
        if (!Uri.TryCreate(uri.Trim(), UriKind.Absolute, out var parsed) || parsed.Scheme != "otpauth")
        {
            return null;
        }

        var query = parsed.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries);
        foreach (var part in query)
        {
            var pair = part.Split('=', 2);
            if (pair.Length == 2 && pair[0].Equals("secret", StringComparison.OrdinalIgnoreCase))
            {
                return Uri.UnescapeDataString(pair[1]).Replace(" ", string.Empty, StringComparison.Ordinal);
            }
        }

        return null;
    }
}

internal static class Base32Encoding
{
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    public static string Encode(byte[] data)
    {
        if (data.Length == 0)
        {
            return string.Empty;
        }

        var output = new StringBuilder((data.Length * 8 + 4) / 5);
        var buffer = 0;
        var bits = 0;
        foreach (var value in data)
        {
            buffer = (buffer << 8) | value;
            bits += 8;
            while (bits >= 5)
            {
                output.Append(Alphabet[(buffer >> (bits - 5)) & 31]);
                bits -= 5;
            }
        }

        if (bits > 0)
        {
            output.Append(Alphabet[(buffer << (5 - bits)) & 31]);
        }

        return output.ToString();
    }

    public static byte[] Decode(string secret)
    {
        var cleaned = (secret ?? string.Empty).Trim().Replace(" ", string.Empty, StringComparison.Ordinal).TrimEnd('=');
        if (cleaned.Length == 0)
        {
            throw new FormatException("The authenticator secret is empty.");
        }

        var buffer = 0;
        var bits = 0;
        using var output = new MemoryStream((cleaned.Length * 5 / 8) + 1);
        foreach (var character in cleaned)
        {
            var index = Alphabet.IndexOf(char.ToUpperInvariant(character));
            if (index < 0)
            {
                throw new FormatException("The authenticator secret is not valid Base32.");
            }

            buffer = (buffer << 5) | index;
            bits += 5;
            if (bits >= 8)
            {
                output.WriteByte((byte)((buffer >> (bits - 8)) & 0xFF));
                bits -= 8;
            }
        }

        return output.ToArray();
    }
}
