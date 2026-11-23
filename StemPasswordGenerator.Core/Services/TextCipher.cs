using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

namespace StemPasswordGenerator.Services;

public enum TextCipherAlgorithm
{
    Aes256Gcm = 1,
    ChaCha20Poly1305 = 2
}

public enum TextCipherLanguage
{
    Base64 = 0,
    Hex = 1,
    Binary = 2
}

public static class TextCipher
{
    public const int MinimumPasswordLength = 12;
    public const int MinimumDistinctPasswordChars = 4;
    public const int MaximumPlaintextBytes = 256 * 1024;
    public const int CurrentVersion = 1;
    public const int InteractiveMemoryKiB = 16 * 1024;

    private const uint Magic = 0x31435453; // "STC1"
    private const int SaltSize = 16;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int KeySize = 32;
    private const int HeaderSize = 59;
    private const int AssociatedHeaderLength = 31; // magic through salt; nonce is the AEAD nonce
    private const int MaxArgon2Iterations = 4;
    private const int MaxArgon2Parallelism = 8;
    private static readonly byte[] AssociatedLabel = "STEM-TEXT-1"u8.ToArray();
    private static readonly UTF8Encoding Utf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    public static bool IsSupported(TextCipherAlgorithm algorithm) =>
        algorithm is TextCipherAlgorithm.Aes256Gcm
        || (algorithm is TextCipherAlgorithm.ChaCha20Poly1305 && ChaCha20Poly1305.IsSupported);

    public static string? PasswordIssueKey(string? password)
    {
        if (string.IsNullOrWhiteSpace(password) || password.Length < MinimumPasswordLength)
        {
            return "CipherPasswordShort";
        }

        var distinct = 0;
        Span<bool> seen = stackalloc bool[128];
        var extra = new HashSet<int>();
        foreach (var character in password)
        {
            if (character < 128)
            {
                if (seen[character])
                {
                    continue;
                }

                seen[character] = true;
            }
            else if (!extra.Add(character))
            {
                continue;
            }

            distinct++;
            if (distinct >= MinimumDistinctPasswordChars)
            {
                return null;
            }
        }

        return "CipherPasswordSimple";
    }

    public static string Encrypt(string plaintext, string password, TextCipherAlgorithm algorithm, TextCipherLanguage language)
    {
        var blob = EncryptToBlob(plaintext, password, algorithm);
        try
        {
            return Encode(blob, language);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(blob);
        }
    }

    public static byte[] EncryptToBlob(string plaintext, string password, TextCipherAlgorithm algorithm)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        EnsurePassword(password);
        if (plaintext.Length == 0)
        {
            throw new ArgumentException("Type the text to encrypt.", nameof(plaintext));
        }

        if (!IsSupported(algorithm))
        {
            throw new CryptographicException("That cipher is not available on this PC.");
        }

        var utf8 = Utf8.GetBytes(plaintext);
        if (utf8.Length > MaximumPlaintextBytes)
        {
            throw new ArgumentException($"Text is larger than {MaximumPlaintextBytes / 1024} KB.", nameof(plaintext));
        }

        var profile = InteractiveProfile();
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var key = DeriveKey(password, salt, profile);
        var blob = new byte[HeaderSize + utf8.Length];
        try
        {
            BinaryPrimitives.WriteUInt32LittleEndian(blob, Magic);
            blob[4] = CurrentVersion;
            blob[5] = (byte)algorithm;
            BinaryPrimitives.WriteInt32LittleEndian(blob.AsSpan(6), profile.MemoryKiB);
            BinaryPrimitives.WriteInt32LittleEndian(blob.AsSpan(10), profile.Iterations);
            blob[14] = (byte)profile.Parallelism;
            salt.CopyTo(blob.AsSpan(15, SaltSize));
            nonce.CopyTo(blob.AsSpan(31, NonceSize));
            Seal(algorithm, key, nonce, utf8, blob.AsSpan(HeaderSize), blob.AsSpan(43, TagSize), BoundAssociatedData(blob));
            return blob;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(blob);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(utf8);
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(salt);
            CryptographicOperations.ZeroMemory(nonce);
        }
    }

    public static string Decrypt(string encoded, string password)
    {
        var text = Decrypt(encoded, password, out var blob);
        CryptographicOperations.ZeroMemory(blob);
        return text;
    }

    public static string Decrypt(string encoded, string password, out byte[] blob)
    {
        ArgumentNullException.ThrowIfNull(encoded);
        EnsurePassword(password);
        blob = Decode(encoded);
        try
        {
            return DecryptBlob(blob, password);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(blob);
            blob = [];
            throw;
        }
    }

    public static TextCipherLanguage DetectLanguage(ReadOnlySpan<char> encoded)
    {
        if (LooksLikeBinary(encoded))
        {
            return TextCipherLanguage.Binary;
        }

        return LooksLikeHex(encoded) ? TextCipherLanguage.Hex : TextCipherLanguage.Base64;
    }

    public static string Encode(ReadOnlySpan<byte> blob, TextCipherLanguage language) =>
        language switch
        {
            TextCipherLanguage.Hex => Convert.ToHexString(blob),
            TextCipherLanguage.Binary => ToBinary(blob),
            _ => Convert.ToBase64String(blob)
        };

    public static byte[] Decode(string encoded)
    {
        if (string.IsNullOrWhiteSpace(encoded))
        {
            throw new CryptographicException("Paste the ciphertext to decrypt.");
        }

        Exception? last = null;
        var order = LooksLikeBinary(encoded)
            ? new[] { TextCipherLanguage.Binary, TextCipherLanguage.Base64, TextCipherLanguage.Hex }
            : new[] { TextCipherLanguage.Base64, TextCipherLanguage.Hex, TextCipherLanguage.Binary };

        foreach (var language in order)
        {
            try
            {
                var blob = DecodeAs(encoded, language);
                if (HasStemHeader(blob))
                {
                    return blob;
                }

                CryptographicOperations.ZeroMemory(blob);
            }
            catch (Exception ex) when (ex is FormatException or CryptographicException)
            {
                last = ex;
            }
        }

        throw new CryptographicException("Could not read that ciphertext.", last);
    }

    internal static Argon2Profile InteractiveProfile()
    {
        var current = Argon2Profile.Current;
        return new Argon2Profile(
            Math.Min(current.MemoryKiB, InteractiveMemoryKiB),
            Math.Min(current.Iterations, 2),
            current.Parallelism);
    }

    private static string DecryptBlob(byte[] blob, string password)
    {
        if (!HasStemHeader(blob) || blob[4] != CurrentVersion)
        {
            throw new CryptographicException("This is not a Stem text cipher.");
        }

        var algorithm = (TextCipherAlgorithm)blob[5];
        if (algorithm is not (TextCipherAlgorithm.Aes256Gcm or TextCipherAlgorithm.ChaCha20Poly1305)
            || !IsSupported(algorithm))
        {
            throw new CryptographicException("That cipher is not available on this PC.");
        }

        var memoryKiB = BinaryPrimitives.ReadInt32LittleEndian(blob.AsSpan(6));
        var iterations = BinaryPrimitives.ReadInt32LittleEndian(blob.AsSpan(10));
        var parallelism = blob[14];
        if (memoryKiB < Argon2Profile.MinimumMemoryKiB
            || memoryKiB > Argon2Profile.MaximumMemoryKiB
            || iterations is < 1 or > MaxArgon2Iterations
            || parallelism is < 1 or > MaxArgon2Parallelism)
        {
            throw new CryptographicException("This is not a Stem text cipher.");
        }

        var salt = blob.AsSpan(15, SaltSize).ToArray();
        var key = DeriveKey(password, salt, new Argon2Profile(memoryKiB, iterations, parallelism));
        var plaintext = new byte[blob.Length - HeaderSize];
        try
        {
            Open(
                algorithm,
                key,
                blob.AsSpan(31, NonceSize),
                blob.AsSpan(HeaderSize),
                blob.AsSpan(43, TagSize),
                plaintext,
                BoundAssociatedData(blob),
                AssociatedLabel);
            return Utf8.GetString(plaintext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(salt);
        }
    }

    private static void Seal(
        TextCipherAlgorithm algorithm,
        byte[] key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertext,
        Span<byte> tag,
        ReadOnlySpan<byte> associatedData)
    {
        if (algorithm is TextCipherAlgorithm.ChaCha20Poly1305)
        {
            using var chacha = new ChaCha20Poly1305(key);
            chacha.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
            return;
        }

        using var aes = new AesGcm(key, TagSize);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
    }

    private static void Open(
        TextCipherAlgorithm algorithm,
        byte[] key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        Span<byte> plaintext,
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> legacyAssociatedData)
    {
        try
        {
            OpenOnce(algorithm, key, nonce, ciphertext, tag, plaintext, associatedData);
        }
        catch (CryptographicException)
        {
            try
            {
                OpenOnce(algorithm, key, nonce, ciphertext, tag, plaintext, legacyAssociatedData);
            }
            catch (CryptographicException)
            {
                CryptographicOperations.ZeroMemory(plaintext);
                throw new CryptographicException("Wrong password or damaged ciphertext.");
            }
        }
    }

    private static void OpenOnce(
        TextCipherAlgorithm algorithm,
        byte[] key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        Span<byte> plaintext,
        ReadOnlySpan<byte> associatedData)
    {
        if (algorithm is TextCipherAlgorithm.ChaCha20Poly1305)
        {
            using var chacha = new ChaCha20Poly1305(key);
            chacha.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
            return;
        }

        using var aes = new AesGcm(key, TagSize);
        aes.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
    }

    private static byte[] DeriveKey(string password, byte[] salt, Argon2Profile profile)
    {
        var passwordBytes = Utf8.GetBytes(password);
        try
        {
            using var argon2 = new Argon2id(passwordBytes)
            {
                Salt = salt,
                DegreeOfParallelism = Math.Clamp(profile.Parallelism, 1, MaxArgon2Parallelism),
                Iterations = Math.Clamp(profile.Iterations, 1, MaxArgon2Iterations),
                MemorySize = Math.Clamp(profile.MemoryKiB, Argon2Profile.MinimumMemoryKiB, Argon2Profile.MaximumMemoryKiB)
            };
            return argon2.GetBytes(KeySize);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
        }
    }

    private static void EnsurePassword(string password)
    {
        var issue = PasswordIssueKey(password);
        if (issue is not null)
        {
            throw new ArgumentException(
                issue == "CipherPasswordSimple"
                    ? "The cipher password needs more variety."
                    : $"The cipher password must be at least {MinimumPasswordLength} characters.",
                nameof(password));
        }
    }

    private static byte[] BoundAssociatedData(byte[] blob)
    {
        var aad = new byte[AssociatedLabel.Length + AssociatedHeaderLength];
        AssociatedLabel.CopyTo(aad, 0);
        Buffer.BlockCopy(blob, 0, aad, AssociatedLabel.Length, AssociatedHeaderLength);
        return aad;
    }

    private static string ToBinary(ReadOnlySpan<byte> blob)
    {
        if (blob.Length == 0)
        {
            return string.Empty;
        }

        var chars = new char[(blob.Length * 9) - 1];
        var position = 0;
        for (var i = 0; i < blob.Length; i++)
        {
            if (i > 0)
            {
                chars[position++] = ' ';
            }

            var value = blob[i];
            chars[position++] = ((value >> 7) & 1) == 0 ? '0' : '1';
            chars[position++] = ((value >> 6) & 1) == 0 ? '0' : '1';
            chars[position++] = ((value >> 5) & 1) == 0 ? '0' : '1';
            chars[position++] = ((value >> 4) & 1) == 0 ? '0' : '1';
            chars[position++] = ((value >> 3) & 1) == 0 ? '0' : '1';
            chars[position++] = ((value >> 2) & 1) == 0 ? '0' : '1';
            chars[position++] = ((value >> 1) & 1) == 0 ? '0' : '1';
            chars[position++] = (value & 1) == 0 ? '0' : '1';
        }

        return new string(chars);
    }

    private static byte[] FromBinary(ReadOnlySpan<char> encoded)
    {
        var bits = 0;
        foreach (var character in encoded)
        {
            if (char.IsWhiteSpace(character))
            {
                continue;
            }

            if (character is not '0' and not '1')
            {
                throw new FormatException("Binary ciphertext may only contain 0 and 1.");
            }

            bits++;
        }

        if (bits == 0 || bits % 8 != 0)
        {
            throw new FormatException("Binary ciphertext length is not a whole number of bytes.");
        }

        var blob = new byte[bits / 8];
        var index = 0;
        var acc = 0;
        var filled = 0;
        foreach (var character in encoded)
        {
            if (char.IsWhiteSpace(character))
            {
                continue;
            }

            acc = (acc << 1) | (character - '0');
            filled++;
            if (filled == 8)
            {
                blob[index++] = (byte)acc;
                acc = 0;
                filled = 0;
            }
        }

        return blob;
    }

    private static byte[] DecodeAs(string encoded, TextCipherLanguage language) =>
        language switch
        {
            TextCipherLanguage.Hex => FromHex(encoded),
            TextCipherLanguage.Binary => FromBinary(encoded),
            _ => FromBase64(encoded)
        };

    private static byte[] FromHex(ReadOnlySpan<char> encoded)
    {
        var digits = 0;
        foreach (var character in encoded)
        {
            if (character is ' ' or '-' or '\r' or '\n' or '\t')
            {
                continue;
            }

            if (!char.IsAsciiHexDigit(character))
            {
                throw new FormatException("Ciphertext is not hexadecimal.");
            }

            digits++;
        }

        if (digits == 0 || digits % 2 != 0)
        {
            throw new FormatException("Ciphertext is not hexadecimal.");
        }

        var blob = new byte[digits / 2];
        var high = -1;
        var index = 0;
        foreach (var character in encoded)
        {
            if (character is ' ' or '-' or '\r' or '\n' or '\t')
            {
                continue;
            }

            var nibble = character switch
            {
                >= '0' and <= '9' => character - '0',
                >= 'A' and <= 'F' => character - 'A' + 10,
                _ => character - 'a' + 10
            };

            if (high < 0)
            {
                high = nibble;
            }
            else
            {
                blob[index++] = (byte)((high << 4) | nibble);
                high = -1;
            }
        }

        return blob;
    }

    private static byte[] FromBase64(ReadOnlySpan<char> encoded)
    {
        var rented = ArrayPool<char>.Shared.Rent(encoded.Length);
        try
        {
            var length = 0;
            foreach (var character in encoded)
            {
                if (char.IsWhiteSpace(character))
                {
                    continue;
                }

                rented[length++] = character;
            }

            var chars = rented.AsSpan(0, length);
            var maxBytes = (length * 3 / 4) + 3;
            var blob = new byte[maxBytes];
            if (!Convert.TryFromBase64Chars(chars, blob, out var written))
            {
                throw new FormatException("Ciphertext is not Base64.");
            }

            if (written == blob.Length)
            {
                return blob;
            }

            var trimmed = blob.AsSpan(0, written).ToArray();
            CryptographicOperations.ZeroMemory(blob);
            return trimmed;
        }
        finally
        {
            ArrayPool<char>.Shared.Return(rented, clearArray: true);
        }
    }

    private static bool HasStemHeader(byte[] blob) =>
        blob.Length is >= HeaderSize + 1 and <= HeaderSize + MaximumPlaintextBytes
        && BinaryPrimitives.ReadUInt32LittleEndian(blob) == Magic;

    private static bool LooksLikeBinary(ReadOnlySpan<char> encoded)
    {
        var bits = 0;
        foreach (var character in encoded)
        {
            if (char.IsWhiteSpace(character))
            {
                continue;
            }

            if (character is not '0' and not '1')
            {
                return false;
            }

            bits++;
        }

        return bits >= 8 && bits % 8 == 0;
    }

    private static bool LooksLikeHex(ReadOnlySpan<char> encoded)
    {
        var digits = 0;
        foreach (var character in encoded)
        {
            if (character is ' ' or '-' or '\r' or '\n' or '\t')
            {
                continue;
            }

            if (!char.IsAsciiHexDigit(character))
            {
                return false;
            }

            digits++;
        }

        return digits >= 8 && digits % 2 == 0;
    }
}
