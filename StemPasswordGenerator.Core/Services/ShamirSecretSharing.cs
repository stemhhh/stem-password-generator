using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace StemPasswordGenerator.Services;

public sealed class ShamirCard
{
    public int Index { get; init; }

    public string FileName { get; init; } = string.Empty;

    public string Body { get; init; } = string.Empty;

    public string Token { get; init; } = string.Empty;
}

public static class ShamirSecretSharing
{
    public const int Threshold = 2;
    public const int TotalShares = 3;
    public const int MaximumSecretBytes = 128;
    public const string BeginMarker = "-----BEGIN STEM SHAMIR-----";
    public const string EndMarker = "-----END STEM SHAMIR-----";

    private const byte Version = 1;
    private static readonly byte[] Magic = "SSG1"u8.ToArray();

    public static IReadOnlyList<ShamirCard> SplitPassword(string masterPassword, string personName, DateTimeOffset createdUtc)
    {
        VaultCryptography.EnsureMasterPassword(masterPassword);
        var secret = Encoding.UTF8.GetBytes(masterPassword);
        try
        {
            if (secret.Length > MaximumSecretBytes)
            {
                throw new ArgumentException("The master password is too long to print on Shamir cards.", nameof(masterPassword));
            }

            var shares = Split(secret, TotalShares, Threshold);
            var cards = new ShamirCard[TotalShares];
            var person = string.IsNullOrWhiteSpace(personName) ? "Stem" : personName.Trim();
            var date = createdUtc.ToLocalTime().ToString("yyyy-MM-dd");
            for (var i = 0; i < shares.Length; i++)
            {
                var index = i + 1;
                var token = EncodeToken(index, TotalShares, shares[i]);
                cards[i] = new ShamirCard
                {
                    Index = index,
                    FileName = $"stem-shamir-{index}-of-{TotalShares}.txt",
                    Token = token,
                    Body = FormatCard(index, TotalShares, person, date, token)
                };
            }

            return cards;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    public static string CombinePassword(IReadOnlyList<string> cards)
    {
        ArgumentNullException.ThrowIfNull(cards);
        var tokens = new List<string>(cards.Count);
        for (var i = 0; i < cards.Count; i++)
        {
            if (TryExtractToken(cards[i], out var token))
            {
                tokens.Add(token);
            }
        }

        if (tokens.Count < Threshold)
        {
            throw new CryptographicException("Need any 2 Shamir cards.");
        }

        var points = new List<(byte X, byte[] Ys)>(tokens.Count);
        var length = -1;
        var seen = new HashSet<byte>();
        foreach (var token in tokens)
        {
            var (index, total, payload) = DecodeToken(token);
            try
            {
                if (total != TotalShares || index is < 1 or > TotalShares || !seen.Add((byte)index))
                {
                    continue;
                }

                var ys = ParsePayload(payload, (byte)index);
                if (length < 0)
                {
                    length = ys.Length;
                }
                else if (ys.Length != length)
                {
                    throw new CryptographicException("Those Shamir cards do not match.");
                }

                points.Add(((byte)index, ys));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(payload);
            }
        }

        if (points.Count < Threshold)
        {
            for (var i = 0; i < points.Count; i++)
            {
                CryptographicOperations.ZeroMemory(points[i].Ys);
            }

            throw new CryptographicException("Need any 2 Shamir cards.");
        }

        byte[] secret;
        try
        {
            secret = Combine(points);
        }
        catch
        {
            for (var i = 0; i < points.Count; i++)
            {
                CryptographicOperations.ZeroMemory(points[i].Ys);
            }

            throw;
        }

        try
        {
            return Encoding.UTF8.GetString(secret);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
            for (var i = 0; i < points.Count; i++)
            {
                CryptographicOperations.ZeroMemory(points[i].Ys);
            }
        }
    }

    public static bool TryExtractToken(string? text, out string token)
    {
        token = string.Empty;
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        var start = text.IndexOf("STEM2-", StringComparison.OrdinalIgnoreCase);
        if (start < 0)
        {
            return false;
        }

        var end = start;
        while (end < text.Length)
        {
            var c = text[end];
            if (char.IsWhiteSpace(c) || c == '\r' || c == '\n')
            {
                break;
            }

            end++;
        }

        token = text[start..end].Trim();
        return token.StartsWith("STEM2-", StringComparison.OrdinalIgnoreCase);
    }

    internal static byte[][] Split(byte[] secret, int shares, int threshold)
    {
        if (secret.Length == 0 || shares != TotalShares || threshold != Threshold)
        {
            throw new ArgumentOutOfRangeException(nameof(shares));
        }

        var coeffs = RandomNumberGenerator.GetBytes(secret.Length);
        var result = new byte[shares][];
        for (var s = 0; s < shares; s++)
        {
            result[s] = new byte[secret.Length];
        }

        try
        {
            for (var i = 0; i < secret.Length; i++)
            {
                var a = coeffs[i];
                if (a == 0)
                {
                    a = 1;
                }

                for (var s = 0; s < shares; s++)
                {
                    var x = (byte)(s + 1);
                    result[s][i] = (byte)(secret[i] ^ Gf.Mul(a, x));
                }
            }

            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(coeffs);
        }
    }

    internal static byte[] Combine(IReadOnlyList<(byte X, byte[] Ys)> points)
    {
        var length = points[0].Ys.Length;
        var secret = new byte[length];
        var sample = new (byte X, byte Y)[points.Count];
        for (var i = 0; i < length; i++)
        {
            for (var p = 0; p < points.Count; p++)
            {
                sample[p] = (points[p].X, points[p].Ys[i]);
            }

            secret[i] = Interpolate(sample);
        }

        return secret;
    }

    private static byte Interpolate(IReadOnlyList<(byte X, byte Y)> points)
    {
        byte secret = 0;
        for (var i = 0; i < points.Count; i++)
        {
            byte num = 1;
            byte den = 1;
            for (var j = 0; j < points.Count; j++)
            {
                if (i == j)
                {
                    continue;
                }

                num = Gf.Mul(num, points[j].X);
                den = Gf.Mul(den, (byte)(points[i].X ^ points[j].X));
            }

            secret ^= Gf.Mul(points[i].Y, Gf.Mul(num, Gf.Inv(den)));
        }

        return secret;
    }

    private static string EncodeToken(int index, int total, byte[] ys)
    {
        var payload = new byte[10 + ys.Length + 4];
        Magic.CopyTo(payload, 0);
        payload[4] = Version;
        payload[5] = Threshold;
        payload[6] = (byte)total;
        payload[7] = (byte)index;
        BinaryPrimitives.WriteUInt16LittleEndian(payload.AsSpan(8, 2), (ushort)ys.Length);
        ys.CopyTo(payload.AsSpan(10));
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(payload.AsSpan(0, 10 + ys.Length), hash);
        hash[..4].CopyTo(payload.AsSpan(10 + ys.Length, 4));
        try
        {
            var grouped = Group(Base32Encoding.Encode(payload));
            return $"STEM2-{index}-{total}-{grouped}";
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload);
            CryptographicOperations.ZeroMemory(hash);
        }
    }

    private static (int Index, int Total, byte[] Payload) DecodeToken(string token)
    {
        var parts = token.Split('-', 4, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 4
            || !parts[0].Equals("STEM2", StringComparison.OrdinalIgnoreCase)
            || !int.TryParse(parts[1], out var index)
            || !int.TryParse(parts[2], out var total))
        {
            throw new CryptographicException("That is not a Stem Shamir card.");
        }

        byte[] payload;
        try
        {
            payload = Base32Encoding.Decode(parts[3].Replace("-", string.Empty, StringComparison.Ordinal));
        }
        catch (FormatException)
        {
            throw new CryptographicException("That is not a Stem Shamir card.");
        }

        return (index, total, payload);
    }

    private static byte[] ParsePayload(byte[] payload, byte expectedIndex)
    {
        if (payload.Length < 14)
        {
            throw new CryptographicException("That Shamir card is damaged.");
        }

        if (payload[0] != Magic[0] || payload[1] != Magic[1] || payload[2] != Magic[2] || payload[3] != Magic[3]
            || payload[4] != Version || payload[5] != Threshold)
        {
            throw new CryptographicException("That Shamir card is damaged.");
        }

        var length = BinaryPrimitives.ReadUInt16LittleEndian(payload.AsSpan(8, 2));
        if (payload[6] != TotalShares || payload[7] != expectedIndex
            || length == 0 || length > MaximumSecretBytes || payload.Length != 14 + length)
        {
            throw new CryptographicException("That Shamir card is damaged.");
        }

        var body = 10 + length;
        var expected = SHA256.HashData(payload.AsSpan(0, body));
        if (!CryptographicOperations.FixedTimeEquals(expected.AsSpan(0, 4), payload.AsSpan(body, 4)))
        {
            throw new CryptographicException("That Shamir card is damaged.");
        }

        var ys = new byte[length];
        payload.AsSpan(10, length).CopyTo(ys);
        return ys;
    }

    private static string Group(string value)
    {
        var builder = new StringBuilder(value.Length + value.Length / 4);
        for (var i = 0; i < value.Length; i++)
        {
            if (i > 0 && i % 5 == 0)
            {
                builder.Append('-');
            }

            builder.Append(value[i]);
        }

        return builder.ToString();
    }

    private static string FormatCard(int index, int total, string person, string date, string token)
    {
        return string.Join(Environment.NewLine,
        [
            UiStrings.Get("ShamirCardTitle"),
            UiStrings.Format("ShamirCardMeta", index, total, Threshold),
            UiStrings.Format("ShamirCardPerson", person),
            UiStrings.Format("ShamirCardDate", date),
            string.Empty,
            UiStrings.Get("ShamirCardKeepApart"),
            string.Empty,
            BeginMarker,
            token,
            EndMarker
        ]);
    }

    private static class Gf
    {
        private static readonly byte[] Exp = new byte[512];
        private static readonly byte[] Log = new byte[256];

        static Gf()
        {
            byte x = 1;
            for (var i = 0; i < 255; i++)
            {
                Exp[i] = x;
                Log[x] = (byte)i;
                x ^= Xtime(x);
            }

            for (var i = 255; i < 512; i++)
            {
                Exp[i] = Exp[i - 255];
            }
        }

        public static byte Mul(byte a, byte b)
        {
            if (a == 0 || b == 0)
            {
                return 0;
            }

            return Exp[Log[a] + Log[b]];
        }

        public static byte Inv(byte a)
        {
            if (a == 0)
            {
                throw new CryptographicException("That Shamir card is damaged.");
            }

            return Exp[255 - Log[a]];
        }

        private static byte Xtime(byte a)
        {
            var hi = (a & 0x80) != 0;
            a = (byte)(a << 1);
            return hi ? (byte)(a ^ 0x1B) : a;
        }
    }
}
