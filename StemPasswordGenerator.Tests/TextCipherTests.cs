using System.Security.Cryptography;
using StemPasswordGenerator.Services;
using Xunit;

namespace StemPasswordGenerator.Tests;

public sealed class TextCipherTests : IDisposable
{
    public TextCipherTests()
    {
        Argon2Profile.Use(new Argon2Profile(8 * 1024, 1, 1));
    }

    public void Dispose() => Argon2Profile.ResetToMachine();

    [Theory]
    [InlineData(TextCipherAlgorithm.Aes256Gcm, TextCipherLanguage.Base64)]
    [InlineData(TextCipherAlgorithm.Aes256Gcm, TextCipherLanguage.Hex)]
    [InlineData(TextCipherAlgorithm.Aes256Gcm, TextCipherLanguage.Binary)]
    [InlineData(TextCipherAlgorithm.ChaCha20Poly1305, TextCipherLanguage.Base64)]
    [InlineData(TextCipherAlgorithm.ChaCha20Poly1305, TextCipherLanguage.Hex)]
    [InlineData(TextCipherAlgorithm.ChaCha20Poly1305, TextCipherLanguage.Binary)]
    public void EncryptThenDecrypt_RoundTrips(TextCipherAlgorithm algorithm, TextCipherLanguage language)
    {
        if (!TextCipher.IsSupported(algorithm))
        {
            return;
        }

        const string plaintext = "Notas locales — Ñandú 🔐";
        const string password = "military-grade-12";
        var encoded = TextCipher.Encrypt(plaintext, password, algorithm, language);

        Assert.False(string.IsNullOrWhiteSpace(encoded));
        Assert.DoesNotContain(plaintext, encoded, StringComparison.Ordinal);
        Assert.Equal(language, TextCipher.DetectLanguage(encoded));
        Assert.Equal(plaintext, TextCipher.Decrypt(encoded, password));
    }

    [Fact]
    public void BinaryLanguage_IsOnlyZerosAndOnes()
    {
        var encoded = TextCipher.Encrypt("hello stem", "military-grade-12", TextCipherAlgorithm.Aes256Gcm, TextCipherLanguage.Binary);
        Assert.Matches("^[01 ]+$", encoded);
        Assert.Contains(' ', encoded);
        Assert.Equal(TextCipherLanguage.Binary, TextCipher.DetectLanguage(encoded));
    }

    [Fact]
    public void Decrypt_WrongPassword_Fails()
    {
        var encoded = TextCipher.Encrypt("secret note", "military-grade-12", TextCipherAlgorithm.Aes256Gcm, TextCipherLanguage.Base64);
        Assert.Throws<CryptographicException>(() => TextCipher.Decrypt(encoded, "military-grade-99"));
    }

    [Fact]
    public void Decrypt_TamperedCiphertext_Fails()
    {
        var encoded = TextCipher.Encrypt("secret note", "military-grade-12", TextCipherAlgorithm.Aes256Gcm, TextCipherLanguage.Hex);
        var chars = encoded.ToCharArray();
        chars[^4] = chars[^4] == 'A' ? 'B' : 'A';
        var tampered = new string(chars);
        Assert.Throws<CryptographicException>(() => TextCipher.Decrypt(tampered, "military-grade-12"));
    }

    [Fact]
    public void ShortPassword_IsRejected()
    {
        Assert.Throws<ArgumentException>(() =>
            TextCipher.Encrypt("note", "short", TextCipherAlgorithm.Aes256Gcm, TextCipherLanguage.Base64));
    }

    [Fact]
    public void EncodeLanguages_DecodeToTheSameBlob()
    {
        var blob = TextCipher.EncryptToBlob("hello stem", "military-grade-12", TextCipherAlgorithm.Aes256Gcm);
        var base64 = TextCipher.Encode(blob, TextCipherLanguage.Base64);
        var hex = TextCipher.Encode(blob, TextCipherLanguage.Hex);
        var binary = TextCipher.Encode(blob, TextCipherLanguage.Binary);

        Assert.Equal(blob, TextCipher.Decode(base64));
        Assert.Equal(blob, TextCipher.Decode(hex));
        Assert.Equal(blob, TextCipher.Decode(binary));
        Assert.Equal("hello stem", TextCipher.Decrypt(binary, "military-grade-12"));
    }

    [Fact]
    public void InteractiveProfile_CapsBelowVaultUnlock()
    {
        Argon2Profile.Use(new Argon2Profile(48 * 1024, 3, 2));
        var profile = TextCipher.InteractiveProfile();
        Assert.Equal(TextCipher.InteractiveMemoryKiB, profile.MemoryKiB);
        Assert.Equal(2, profile.Iterations);
        Assert.Equal(2, profile.Parallelism);
    }

    [Fact]
    public void EmptyPlaintext_IsRejected()
    {
        Assert.Throws<ArgumentException>(() =>
            TextCipher.Encrypt("", "military-grade-12", TextCipherAlgorithm.Aes256Gcm, TextCipherLanguage.Base64));
    }

    [Fact]
    public void RepetitivePassword_IsRejected()
    {
        Assert.Equal("CipherPasswordSimple", TextCipher.PasswordIssueKey("aaaaaaaaaaaa"));
        Assert.Throws<ArgumentException>(() =>
            TextCipher.Encrypt("note", "aaaaaaaaaaaa", TextCipherAlgorithm.Aes256Gcm, TextCipherLanguage.Base64));
    }

    [Fact]
    public void Decode_BinaryLookingJunk_DoesNotPretendToBeStem()
    {
        Assert.Throws<CryptographicException>(() => TextCipher.Decode("01001101 01000001"));
    }

    [Fact]
    public void TamperedSalt_FailsClosed()
    {
        var blob = TextCipher.EncryptToBlob("secret note", "military-grade-12", TextCipherAlgorithm.Aes256Gcm);
        blob[20] ^= 0xFF;
        var encoded = TextCipher.Encode(blob, TextCipherLanguage.Base64);
        Assert.Throws<CryptographicException>(() => TextCipher.Decrypt(encoded, "military-grade-12"));
    }

    [Fact]
    public void ImpossibleKdfParameters_FailClosed()
    {
        var blob = TextCipher.EncryptToBlob("secret note", "military-grade-12", TextCipherAlgorithm.Aes256Gcm);
        System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(blob.AsSpan(6), 1);
        var encoded = TextCipher.Encode(blob, TextCipherLanguage.Hex);
        Assert.Throws<CryptographicException>(() => TextCipher.Decrypt(encoded, "military-grade-12"));
    }

    [Fact]
    public void PasswordIssueKey_AcceptsVariedSecret()
    {
        Assert.Null(TextCipher.PasswordIssueKey("military-grade-12"));
        Assert.Equal("CipherPasswordShort", TextCipher.PasswordIssueKey("short"));
    }
}
