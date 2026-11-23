using System.Security.Cryptography;
using StemPasswordGenerator.Models;
using StemPasswordGenerator.Services;
using Xunit;

namespace StemPasswordGenerator.Tests;

[Collection("FastCrypto")]
public sealed class PortableVaultFileTests
{
    private const string Master = "correct-horse-battery-staple";
    private readonly VaultCryptography _crypto = new();

    [Fact]
    public void Pack_RoundTripsInnerCiphertextAndOpensWithTheSameMaster()
    {
        var document = new VaultDocument
        {
            Items =
            {
                new VaultItem { Title = "Mail", Username = "enmanuel", Password = "s3cret!" }
            }
        };
        var inner = _crypto.Encrypt(document, Master);
        var packed = PortableVaultFile.Pack(inner);

        Assert.True(PortableVaultFile.LooksLike(packed));
        Assert.False(PortableVaultFile.LooksLikeDpapi(packed));
        Assert.True(PortableVaultFile.TryReadInner(packed, out var restored));
        Assert.Equal(inner, restored);

        var opened = _crypto.Decrypt(restored, Master);
        Assert.Equal("s3cret!", opened.Items[0].Password);
        Assert.Equal("Mail", opened.Items[0].Title);
    }

    [Fact]
    public void RawSpg1_IsAcceptedAsPortableInner()
    {
        var inner = _crypto.Encrypt(new VaultDocument
        {
            Items = { new VaultItem { Title = "App", Password = "hidden-secret" } }
        }, Master);

        Assert.True(VaultCryptography.LooksLikeInner(inner));
        Assert.True(PortableVaultFile.TryReadInner(inner, out var restored));
        Assert.Equal("hidden-secret", _crypto.Decrypt(restored, Master).Items[0].Password);
    }

    [Fact]
    public void DpapiVault_IsRejected()
    {
        var blob = new byte[] { (byte)'S', (byte)'P', (byte)'G', (byte)'D', 1, 9, 9, 9 };
        Assert.True(PortableVaultFile.LooksLikeDpapi(blob));
        Assert.False(PortableVaultFile.TryReadInner(blob, out var inner));
        Assert.Empty(inner);
    }

    [Fact]
    public void WrongMaster_FailsClosed()
    {
        var inner = _crypto.Encrypt(new VaultDocument
        {
            Items = { new VaultItem { Title = "Bank", Password = "do-not-leak" } }
        }, Master);
        var packed = PortableVaultFile.Pack(inner);

        Assert.True(PortableVaultFile.TryReadInner(packed, out var restored));
        Assert.Throws<CryptographicException>(() => _crypto.Decrypt(restored, "wrong-horse-battery-staple"));
    }

    [Fact]
    public void TamperedPack_IsRejected()
    {
        var inner = _crypto.Encrypt(new VaultDocument(), Master);
        var packed = PortableVaultFile.Pack(inner);
        packed[^1] ^= 0x5A;
        Assert.True(PortableVaultFile.TryReadInner(packed, out var restored));
        Assert.Throws<CryptographicException>(() => _crypto.Decrypt(restored, Master));
    }

    [Fact]
    public void SharePasswordBlob_DoesNotOpenWithMaster()
    {
        var share = _crypto.Encrypt(new VaultDocument
        {
            Items = { new VaultItem { Title = "Shared", Password = "share-secret" } }
        }, "share-password-ok");

        Assert.True(PortableVaultFile.TryReadInner(share, out var inner));
        Assert.Throws<CryptographicException>(() => _crypto.Decrypt(inner, Master));
        Assert.Equal("share-secret", _crypto.Decrypt(inner, "share-password-ok").Items[0].Password);
    }
}
