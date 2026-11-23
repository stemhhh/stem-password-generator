using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;
using StemPasswordGenerator.Models;

namespace StemPasswordGenerator.Services;

public sealed record RecoveryMaterials(string Key, string Phrase);

public sealed record RecoveryHash(byte[] Salt, int MemoryKiB, int Iterations, int Parallelism, byte[] Digest);

public sealed record RecoveryVerifier(RecoveryHash Key, RecoveryHash Phrase);

public static class VaultRecovery
{
    public const int WordCount = 7;
    public const int KeyByteCount = 16;
    public const string KeyPrefix = "STEMR";
    public const string VerifierFileName = "recovery.srv";

    private const byte Version = 1;
    private const int SaltSize = 16;
    private const int DigestSize = 32;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int HashRecordSize = SaltSize + 4 + 4 + 1 + DigestSize;
    private static readonly byte[] VerifierMagic = "SRV1"u8.ToArray();
    private static readonly byte[] ExportMagic = "SRX1"u8.ToArray();
    private static readonly byte[] ExportAd = "STEM-RECOVERY-EXPORT"u8.ToArray();
    private const string KeyDomain = "STEM-RECOVERY-KEY";
    private const string PhraseDomain = "STEM-RECOVERY-PHRASE";

    public static RecoveryMaterials Create(string? masterPassword)
    {
        var key = FormatKey(RandomNumberGenerator.GetBytes(KeyByteCount));
        var phrase = CreatePhrase(masterPassword);
        return new RecoveryMaterials(key, phrase);
    }

    public static string NormalizeKey(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var builder = new StringBuilder(value.Length);
        foreach (var character in value.Trim().ToUpperInvariant())
        {
            if (character is '-' or ' ' or '\r' or '\n' or '\t')
            {
                continue;
            }

            builder.Append(character);
        }

        return builder.ToString();
    }

    public static string NormalizePhrase(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var parts = value
            .Trim()
            .ToLowerInvariant()
            .Split([' ', '\t', '\r', '\n', '-', ',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return string.Join(' ', parts);
    }

    public static bool LooksLikeKey(string? value)
    {
        var key = NormalizeKey(value);
        return key.StartsWith(KeyPrefix, StringComparison.Ordinal) && key.Length >= KeyPrefix.Length + 8;
    }

    public static byte[] MacVerifier(byte[] verifierBlob, byte[] vaultKey)
    {
        ArgumentNullException.ThrowIfNull(verifierBlob);
        ArgumentNullException.ThrowIfNull(vaultKey);
        using var hmac = new HMACSHA256(vaultKey);
        return hmac.ComputeHash(verifierBlob);
    }

    public static bool VerifyMac(byte[] verifierBlob, byte[] vaultKey, byte[]? mac)
    {
        if (mac is not { Length: DigestSize })
        {
            return false;
        }

        var actual = MacVerifier(verifierBlob, vaultKey);
        try
        {
            return CryptographicOperations.FixedTimeEquals(actual, mac);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(actual);
        }
    }

    public static RecoveryVerifier CreateVerifier(RecoveryMaterials materials)
    {
        ArgumentNullException.ThrowIfNull(materials);
        return new RecoveryVerifier(
            HashSecret(KeyDomain, NormalizeKey(materials.Key)),
            HashSecret(PhraseDomain, NormalizePhrase(materials.Phrase)));
    }

    public static bool VerifyKey(string? key, RecoveryVerifier verifier)
    {
        ArgumentNullException.ThrowIfNull(verifier);
        return VerifySecret(KeyDomain, NormalizeKey(key), verifier.Key);
    }

    public static bool VerifyPhrase(string? phrase, RecoveryVerifier verifier)
    {
        ArgumentNullException.ThrowIfNull(verifier);
        return VerifySecret(PhraseDomain, NormalizePhrase(phrase), verifier.Phrase);
    }

    public static byte[] SerializeVerifier(RecoveryVerifier verifier)
    {
        ArgumentNullException.ThrowIfNull(verifier);
        var blob = new byte[5 + HashRecordSize * 2];
        VerifierMagic.CopyTo(blob, 0);
        blob[4] = Version;
        WriteHash(blob.AsSpan(5), verifier.Key);
        WriteHash(blob.AsSpan(5 + HashRecordSize), verifier.Phrase);
        return blob;
    }

    public static bool LooksLikeVerifier(byte[]? blob)
        => blob is { Length: >= 5 + HashRecordSize * 2 }
            && blob.AsSpan(0, 4).SequenceEqual(VerifierMagic)
            && blob[4] == Version;

    public static RecoveryVerifier ParseVerifier(byte[] blob)
    {
        if (!LooksLikeVerifier(blob))
        {
            throw new CryptographicException("That is not a Stem recovery verifier.");
        }

        return new RecoveryVerifier(ReadHash(blob.AsSpan(5)), ReadHash(blob.AsSpan(5 + HashRecordSize)));
    }

    public static byte[] ProtectWithPassword(RecoveryMaterials materials, string extraPassword)
    {
        ArgumentNullException.ThrowIfNull(materials);
        VaultCryptography.EnsureMasterPassword(extraPassword);
        var plaintext = Encoding.UTF8.GetBytes(materials.Key + "\n" + materials.Phrase);
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var profile = Argon2Profile.Current;
        var wrapKey = Derive(extraPassword, salt, profile);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagSize];
        try
        {
            using (var aes = new AesGcm(wrapKey, TagSize))
            {
                aes.Encrypt(nonce, plaintext, ciphertext, tag, ExportAd);
            }

            var blob = new byte[4 + 1 + 1 + 4 + 4 + 1 + SaltSize + NonceSize + TagSize + ciphertext.Length];
            ExportMagic.CopyTo(blob, 0);
            blob[4] = Version;
            blob[5] = 1;
            BinaryPrimitives.WriteInt32LittleEndian(blob.AsSpan(6), profile.MemoryKiB);
            BinaryPrimitives.WriteInt32LittleEndian(blob.AsSpan(10), profile.Iterations);
            blob[14] = (byte)profile.Parallelism;
            salt.CopyTo(blob.AsSpan(15));
            nonce.CopyTo(blob.AsSpan(31));
            tag.CopyTo(blob.AsSpan(43));
            ciphertext.CopyTo(blob.AsSpan(59));
            return blob;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(wrapKey);
            CryptographicOperations.ZeroMemory(ciphertext);
        }
    }

    public static bool LooksLikePasswordExport(byte[]? blob)
        => blob is { Length: >= 59 }
            && blob.AsSpan(0, 4).SequenceEqual(ExportMagic)
            && blob[4] == Version;

    public static RecoveryMaterials OpenWithPassword(byte[] blob, string extraPassword)
    {
        ArgumentNullException.ThrowIfNull(blob);
        VaultCryptography.EnsureMasterPassword(extraPassword);
        if (!LooksLikePasswordExport(blob) || blob[5] != 1)
        {
            throw new CryptographicException("That is not a Stem recovery export.");
        }

        var memory = BinaryPrimitives.ReadInt32LittleEndian(blob.AsSpan(6));
        var iterations = BinaryPrimitives.ReadInt32LittleEndian(blob.AsSpan(10));
        var parallelism = blob[14];
        var salt = blob.AsSpan(15, SaltSize).ToArray();
        var nonce = blob.AsSpan(31, NonceSize);
        var tag = blob.AsSpan(43, TagSize);
        var ciphertext = blob.AsSpan(59);
        var wrapKey = Derive(extraPassword, salt, new Argon2Profile(memory, iterations, parallelism));
        var plaintext = new byte[ciphertext.Length];
        try
        {
            using var aes = new AesGcm(wrapKey, TagSize);
            aes.Decrypt(nonce, ciphertext, tag, plaintext, ExportAd);
            return ParseBundle(Encoding.UTF8.GetString(plaintext));
        }
        catch (CryptographicException)
        {
            throw new CryptographicException("Wrong recovery-file password or the file is damaged.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(wrapKey);
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    public static string FormatPrintable(RecoveryMaterials materials, string personName, DateTimeOffset createdUtc)
    {
        ArgumentNullException.ThrowIfNull(materials);
        var person = string.IsNullOrWhiteSpace(personName) ? "Stem" : personName.Trim();
        var date = createdUtc.ToLocalTime().ToString("yyyy-MM-dd");
        return
            $"""
            STEM recovery kit
            Person: {person}
            Printed: {date}

            Recovery key (shown once; Stem stores only a hash):
            {materials.Key}

            Recovery phrase (7 words, issued once when you configure recovery; not the master password):
            {FormatNumberedPhrase(materials.Phrase)}

            {materials.Phrase}

            Forgot the master: Windows Hello + this key, or Windows Hello + this phrase.
            Keep this file apart from the PC. Do not photograph it next to the Shamir cards.
            """;
    }

    public static bool ContainsPlainSecrets(byte[] blob, RecoveryMaterials materials)
    {
        ArgumentNullException.ThrowIfNull(blob);
        ArgumentNullException.ThrowIfNull(materials);
        var text = Encoding.UTF8.GetString(blob);
        return text.Contains(materials.Key, StringComparison.Ordinal)
            || text.Contains(materials.Phrase, StringComparison.Ordinal);
    }

    public static string FormatNumberedPhrase(string? phrase)
    {
        var words = NormalizePhrase(phrase).Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (words.Length == 0)
        {
            return string.Empty;
        }

        var lines = new string[words.Length];
        for (var i = 0; i < words.Length; i++)
        {
            lines[i] = $"{i + 1}. {words[i]}";
        }

        return string.Join(Environment.NewLine, lines);
    }

    private static string CreatePhrase(string? masterPassword)
    {
        var words = WordList.Words;
        var chosen = new string[WordCount];
        var used = new HashSet<string>(StringComparer.Ordinal);
        var normalizedMaster = NormalizePhrase(masterPassword);
        for (var attempt = 0; attempt < 32; attempt++)
        {
            used.Clear();
            for (var i = 0; i < WordCount; i++)
            {
                string word;
                do
                {
                    word = words[RandomNumberGenerator.GetInt32(words.Count)];
                }
                while (!used.Add(word));

                chosen[i] = word;
            }

            var phrase = string.Join(' ', chosen);
            if (!string.Equals(phrase, normalizedMaster, StringComparison.Ordinal)
                && (string.IsNullOrEmpty(normalizedMaster) || !normalizedMaster.Contains(phrase, StringComparison.Ordinal)))
            {
                return phrase;
            }
        }

        return string.Join(' ', chosen);
    }

    private static string FormatKey(byte[] raw)
    {
        try
        {
            return KeyPrefix + "-" + Group(Base32Encoding.Encode(raw));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(raw);
        }
    }

    private static string Group(string value)
    {
        const int size = 5;
        var builder = new StringBuilder(value.Length + value.Length / size);
        for (var i = 0; i < value.Length; i++)
        {
            if (i > 0 && i % size == 0)
            {
                builder.Append('-');
            }

            builder.Append(value[i]);
        }

        return builder.ToString();
    }

    private static RecoveryMaterials ParseBundle(string text)
    {
        var lines = text.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');
        if (lines.Length < 2)
        {
            throw new CryptographicException("That recovery export is damaged.");
        }

        return new RecoveryMaterials(lines[0].Trim(), string.Join('\n', lines.Skip(1)).Trim());
    }

    private static RecoveryHash HashSecret(string domain, string secret)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var profile = Argon2Profile.Current;
        var digest = Derive(domain + "\n" + secret, salt, profile);
        return new RecoveryHash(salt, profile.MemoryKiB, profile.Iterations, profile.Parallelism, digest);
    }

    private static bool VerifySecret(string domain, string secret, RecoveryHash hash)
    {
        if (string.IsNullOrEmpty(secret) || hash.Digest.Length != DigestSize)
        {
            return false;
        }

        var derived = Derive(domain + "\n" + secret, hash.Salt, new Argon2Profile(hash.MemoryKiB, hash.Iterations, hash.Parallelism));
        try
        {
            return CryptographicOperations.FixedTimeEquals(derived, hash.Digest);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(derived);
        }
    }

    private static void WriteHash(Span<byte> destination, RecoveryHash hash)
    {
        hash.Salt.CopyTo(destination);
        BinaryPrimitives.WriteInt32LittleEndian(destination[SaltSize..], hash.MemoryKiB);
        BinaryPrimitives.WriteInt32LittleEndian(destination[(SaltSize + 4)..], hash.Iterations);
        destination[SaltSize + 8] = (byte)hash.Parallelism;
        hash.Digest.CopyTo(destination[(SaltSize + 9)..]);
    }

    private static RecoveryHash ReadHash(ReadOnlySpan<byte> source)
    {
        var salt = source[..SaltSize].ToArray();
        var memory = BinaryPrimitives.ReadInt32LittleEndian(source[SaltSize..]);
        var iterations = BinaryPrimitives.ReadInt32LittleEndian(source[(SaltSize + 4)..]);
        var parallelism = source[SaltSize + 8];
        var digest = source.Slice(SaltSize + 9, DigestSize).ToArray();
        return new RecoveryHash(salt, memory, iterations, parallelism, digest);
    }

    private static byte[] Derive(string secret, byte[] salt, Argon2Profile profile)
    {
        var passwordBytes = Encoding.UTF8.GetBytes(secret);
        try
        {
            using var argon2 = new Argon2id(passwordBytes)
            {
                Salt = salt,
                DegreeOfParallelism = Math.Clamp(profile.Parallelism, 1, 8),
                Iterations = Math.Clamp(profile.Iterations, 1, 4),
                MemorySize = Math.Clamp(profile.MemoryKiB, Argon2Profile.MinimumMemoryKiB, Argon2Profile.MaximumMemoryKiB)
            };
            return argon2.GetBytes(DigestSize);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
        }
    }
}
