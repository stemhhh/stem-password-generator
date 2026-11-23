using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace StemPasswordGenerator.Services;

public static class HibpKAnonymity
{
    public const int PrefixLength = 5;
    public const int SuffixLength = 35;
    public const string RangeHost = "api.pwnedpasswords.com";

    public static string Sha1Hex(string secret)
    {
        ArgumentNullException.ThrowIfNull(secret);
        var utf8 = Encoding.UTF8.GetBytes(secret);
        try
        {
            var hash = SHA1.HashData(utf8);
            try
            {
                return Convert.ToHexString(hash);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(hash);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(utf8);
        }
    }

    public static (string Prefix, string Suffix) SplitHex(string hex)
    {
        if (string.IsNullOrWhiteSpace(hex) || hex.Length != PrefixLength + SuffixLength)
        {
            throw new ArgumentException("Unexpected SHA-1 length.", nameof(hex));
        }

        return (hex[..PrefixLength].ToUpperInvariant(), hex[PrefixLength..].ToUpperInvariant());
    }

    public static Uri RangeUri(string prefix)
    {
        if (!IsRangePrefix(prefix))
        {
            throw new ArgumentException("Range prefix must be 5 hex characters.", nameof(prefix));
        }

        return new Uri($"https://{RangeHost}/range/{prefix.ToUpperInvariant()}");
    }

    public static bool IsRangePrefix(string? prefix)
    {
        if (prefix is null || prefix.Length != PrefixLength)
        {
            return false;
        }

        foreach (var character in prefix)
        {
            if (!char.IsAsciiHexDigit(character))
            {
                return false;
            }
        }

        return true;
    }

    public static bool RequestIsKAnonymous(Uri? uri, string secret)
    {
        if (uri is null || string.IsNullOrEmpty(secret))
        {
            return false;
        }

        if (!string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(uri.Host, RangeHost, StringComparison.OrdinalIgnoreCase)
            || uri.Query.Length > 0
            || uri.Fragment.Length > 0)
        {
            return false;
        }

        var hex = Sha1Hex(secret);
        var (prefix, suffix) = SplitHex(hex);
        if (!string.Equals(uri.AbsolutePath, "/range/" + prefix, StringComparison.OrdinalIgnoreCase)
            || uri.AbsolutePath.Length != "/range/".Length + PrefixLength)
        {
            return false;
        }

        var absolute = uri.AbsoluteUri;
        return !ContainsOrdinal(absolute, hex)
            && !ContainsOrdinal(absolute, suffix);
    }

    public static int? MatchCount(string suffix, string rangeBody)
    {
        if (string.IsNullOrEmpty(suffix) || suffix.Length != SuffixLength || string.IsNullOrEmpty(rangeBody))
        {
            return null;
        }

        foreach (var raw in rangeBody.Split(["\r\n", "\n"], StringSplitOptions.RemoveEmptyEntries))
        {
            var line = raw.Trim();
            var colon = line.IndexOf(':');
            if (colon != SuffixLength)
            {
                continue;
            }

            var lineSuffix = line[..colon];
            if (!lineSuffix.Equals(suffix, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (!int.TryParse(line[(colon + 1)..], NumberStyles.Integer, CultureInfo.InvariantCulture, out var count)
                || count <= 0)
            {
                return null;
            }

            return count;
        }

        return null;
    }

    private static bool ContainsOrdinal(string haystack, string needle) =>
        needle.Length > 0 && haystack.Contains(needle, StringComparison.OrdinalIgnoreCase);
}
