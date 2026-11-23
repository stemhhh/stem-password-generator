using System.Security.Cryptography;
using StemPasswordGenerator.Models;
using StemPasswordGenerator.Services;
using Xunit;

namespace StemPasswordGenerator.Tests;

[Collection("FastCrypto")]
public sealed class LocalHardeningTests
{
    [Fact]
    public void SecretFingerprint_DoesNotTreatOtherTextAsMatch()
    {
        var fingerprint = SecretFingerprint.Hash("clipboard-secret");
        Assert.True(SecretFingerprint.Matches("clipboard-secret", fingerprint));
        Assert.False(SecretFingerprint.Matches("clipboard-secret!", fingerprint));
        Assert.False(SecretFingerprint.Matches("clipboard-secret", []));
    }

    [Fact]
    public void PlatformWrapBlob_RejectsTamperAndTruncation()
    {
        var packed = PlatformWrapBlob.Pack([1, 2, 3, 4]);
        Assert.True(PlatformWrapBlob.LooksLike(packed));
        packed[^1] ^= 0x7F;
        var unpacked = PlatformWrapBlob.Unpack(packed);
        Assert.Equal(4, unpacked.Length);
        Assert.False(PlatformWrapBlob.LooksLike("SPGD"u8.ToArray()));
        Assert.Throws<CryptographicException>(() => PlatformWrapBlob.Unpack([1, 2, 3]));
        Assert.Throws<CryptographicException>(() => PlatformWrapBlob.Unpack(PlatformWrapBlob.Pack([9, 9])[..8]));
    }

    [Fact]
    public void VaultKey_StillEncryptsAfterMemoryProtect()
    {
        var crypto = new VaultCryptography();
        var blob = crypto.Encrypt(new VaultDocument
        {
            Items = { new VaultItem { Title = "mail", Password = "hidden-secret" } }
        }, "correct-horse-battery-staple");
        var opened = crypto.Decrypt(blob, "correct-horse-battery-staple", out var key);
        using (key)
        {
            Assert.False(key.IsDisposed);
            var again = crypto.Encrypt(opened, key);
            var roundTrip = crypto.Decrypt(again, key);
            Assert.Equal("hidden-secret", roundTrip.Items[0].Password);
        }

        Assert.True(key.IsDisposed);
        Assert.Throws<ObjectDisposedException>(() => key.CopyKeyBytes());
    }
}
