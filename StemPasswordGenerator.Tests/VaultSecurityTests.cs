using System.Security.Cryptography;
using StemPasswordGenerator.Models;
using StemPasswordGenerator.Services;
using Xunit;

namespace StemPasswordGenerator.Tests;

[Collection("FastCrypto")]
public sealed class VaultSecurityTests
{
    private const string Master = "correct-horse-battery-staple";
    private readonly VaultCryptography _crypto = new();

    [Fact]
    public void TamperedCiphertext_FailsClosed()
    {
        var blob = _crypto.Encrypt(Sample(), Master);
        blob[^1] ^= 0x5A;

        Assert.Throws<CryptographicException>(() => _crypto.Decrypt(blob, Master));
    }

    [Fact]
    public void TamperedHeaderMagic_FailsClosed()
    {
        var blob = _crypto.Encrypt(Sample(), Master);
        blob[0] ^= 0xFF;

        Assert.Throws<CryptographicException>(() => _crypto.Decrypt(blob, Master));
    }

    [Fact]
    public void TamperedNonce_FailsClosed()
    {
        var blob = _crypto.Encrypt(Sample(), Master);
        blob[31] ^= 0x7E;

        Assert.Throws<CryptographicException>(() => _crypto.Decrypt(blob, Master));
    }

    [Fact]
    public void TamperedTag_FailsClosed()
    {
        var blob = _crypto.Encrypt(Sample(), Master);
        blob[43] ^= 0x11;

        Assert.Throws<CryptographicException>(() => _crypto.Decrypt(blob, Master));
    }

    [Fact]
    public void EmptyBlob_FailsClosed()
    {
        Assert.Throws<CryptographicException>(() => _crypto.Decrypt([], Master));
    }

    [Fact]
    public void WrongSharePassword_CannotReadItems()
    {
        var blob = _crypto.Encrypt(Sample(), Master);
        Assert.Throws<CryptographicException>(() => _crypto.Decrypt(blob, "totally-different-pass"));
    }

    [Fact]
    public void ClearDocument_WipesPasswordHistory()
    {
        var old = new PasswordHistoryEntry { Password = "previous-secret" };
        var document = new VaultDocument
        {
            Items =
            {
                new VaultItem
                {
                    Title = "Netflix",
                    Password = "current-secret",
                    PasswordHistory = [old]
                }
            }
        };

        VaultCryptography.ClearDocument(document);

        Assert.Empty(document.Items);
        Assert.Equal(string.Empty, old.Password);
    }

    [Fact]
    public void ClearDocument_RemovesSecrets()
    {
        var document = Sample();
        VaultCryptography.ClearDocument(document);

        Assert.Empty(document.Items);
        Assert.Equal(string.Empty, document.Settings.PrimaryEmail);
    }

    [Fact]
    public void ClearDocument_WipesMailboxProfilesEvenWithoutItems()
    {
        var profile = new MailboxProfile { Label = "Work", Email = "secret@mail.com", IsDefault = true };
        var document = new VaultDocument
        {
            Settings = new VaultSettings
            {
                PrimaryEmail = "secret@mail.com",
                AliasDomain = "alias.example",
                Profiles = [profile]
            }
        };

        VaultCryptography.ClearDocument(document);

        Assert.Empty(document.Items);
        Assert.Equal(string.Empty, document.Settings.PrimaryEmail);
        Assert.Empty(document.Settings.Profiles);
        Assert.Equal(string.Empty, profile.Email);
        Assert.Equal(string.Empty, profile.Label);
    }

    [Fact]
    public void LowResourceProfile_StillEncrypts()
    {
        Argon2Profile.Use(new Argon2Profile(8 * 1024, 1, 1));
        try
        {
            var opened = _crypto.Decrypt(_crypto.Encrypt(Sample(), Master), Master);
            Assert.Equal("bank", opened.Items[0].Title);
            Assert.Equal("s3cret!", opened.Items[0].Password);
        }
        finally
        {
            Argon2Profile.Use(new Argon2Profile(8 * 1024, 1, 1));
        }
    }

    [Fact]
    public void SessionKey_DoesNotKeepMasterPassword()
    {
        var blob = _crypto.Encrypt(Sample(), Master);
        var opened = _crypto.Decrypt(blob, Master, out var key);
        using (key)
        {
            Assert.False(key.IsDisposed);
            Assert.Equal("s3cret!", opened.Items[0].Password);
            var again = _crypto.Encrypt(opened, key);
            Assert.NotEqual(blob, again);
        }

        Assert.True(key.IsDisposed);
    }

    [Fact]
    public void SessionKey_RejectsTamperedHeaderSalt()
    {
        var blob = _crypto.Encrypt(Sample(), Master);
        var opened = _crypto.Decrypt(blob, Master, out var key);
        using (key)
        {
            blob[20] ^= 0x3C;
            Assert.Throws<CryptographicException>(() => _crypto.Decrypt(blob, key));
            Assert.Equal("s3cret!", opened.Items[0].Password);
        }
    }

    private static VaultDocument Sample() => new()
    {
        Items = { new VaultItem { Title = "bank", Password = "s3cret!", Username = "enmanuel" } }
    };
}

public sealed class Argon2ProfileTests
{
    [Fact]
    public void Detect_StaysInSafeBoundsForLowEndPcs()
    {
        var profile = Argon2Profile.Detect();
        Assert.InRange(profile.MemoryKiB, Argon2Profile.MinimumMemoryKiB, Argon2Profile.MaximumMemoryKiB);
        Assert.InRange(profile.Iterations, 1, 4);
        Assert.InRange(profile.Parallelism, 1, 2);
    }

    [Fact]
    public void LowRamPcs_UseTheLightestKdf()
    {
        var low = Argon2Profile.Create(2, 8);
        Assert.Equal(16 * 1024, low.MemoryKiB);
        Assert.Equal(3, low.Iterations);
        Assert.Equal(1, low.Parallelism);
    }

    [Fact]
    public void MidRamPcs_StayUnder64Mib()
    {
        var mid = Argon2Profile.Create(6, 4);
        Assert.Equal(32 * 1024, mid.MemoryKiB);
        Assert.Equal(3, mid.Iterations);
        Assert.Equal(2, mid.Parallelism);
    }
}

[CollectionDefinition("FastCrypto")]
public sealed class FastCryptoCollection : ICollectionFixture<FastCryptoFixture>
{
}

public sealed class FastCryptoFixture : IDisposable
{
    public FastCryptoFixture()
    {
        Argon2Profile.Use(new Argon2Profile(8 * 1024, 1, 1));
    }

    public void Dispose()
    {
        Argon2Profile.ResetToMachine();
    }
}
