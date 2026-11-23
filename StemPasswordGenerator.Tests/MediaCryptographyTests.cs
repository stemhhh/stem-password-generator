using System.Security.Cryptography;
using StemPasswordGenerator.Services;
using Xunit;

namespace StemPasswordGenerator.Tests;

public sealed class MediaCryptographyTests
{
    [Fact]
    public void MasterKeyWrap_RoundTrips_AndTamperFails()
    {
        var kek = RandomNumberGenerator.GetBytes(32);
        var mmk = MediaCryptography.CreateMasterKey();
        var wrap = MediaCryptography.WrapMasterKey(kek, mmk);

        Assert.False(wrap.AsSpan().SequenceEqual(mmk));
        Assert.Equal(mmk, MediaCryptography.UnwrapMasterKey(kek, wrap));
        wrap[^1] ^= 0x5A;
        Assert.Throws<CryptographicException>(() => MediaCryptography.UnwrapMasterKey(kek, wrap));
    }

    [Fact]
    public async Task File_RoundTripsThroughChunks()
    {
        var mmk = MediaCryptography.CreateMasterKey();
        var id = Guid.NewGuid();
        var fileKey = MediaCryptography.FileKey(mmk, id);
        var plain = Enumerable.Range(0, 3000).Select(static i => (byte)(i * 17)).ToArray();
        using var input = new MemoryStream(plain);
        using var packed = new MemoryStream();
        await MediaCryptography.EncryptAsync(input, packed, fileKey, id, chunkSize: 1024);

        packed.Position = 0;
        Assert.True(MediaCryptography.LooksLikeBlob(packed.ToArray()));
        using var output = new MemoryStream();
        await MediaCryptography.DecryptAsync(packed, output, fileKey, id);
        Assert.Equal(plain, output.ToArray());
    }

    [Fact]
    public async Task File_RejectsWrongIdAndTamperedCiphertext()
    {
        var mmk = MediaCryptography.CreateMasterKey();
        var id = Guid.NewGuid();
        var fileKey = MediaCryptography.FileKey(mmk, id);
        using var packed = new MemoryStream();
        await MediaCryptography.EncryptAsync(new MemoryStream("secret-photo-bytes"u8.ToArray()), packed, fileKey, id, chunkSize: 1024);
        var blob = packed.ToArray();
        blob[^1] ^= 0x22;
        await Assert.ThrowsAsync<CryptographicException>(() =>
            MediaCryptography.DecryptAsync(new MemoryStream(blob), new MemoryStream(), fileKey, id));

        packed.Position = 0;
        await Assert.ThrowsAsync<CryptographicException>(() =>
            MediaCryptography.DecryptAsync(packed, new MemoryStream(), fileKey, Guid.NewGuid()));
    }

    [Fact]
    public void BlobFileName_IsOpaqueGuid()
    {
        var id = Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
        var name = MediaCryptography.BlobFileName(id);
        Assert.Equal("aaaaaaaabbbbccccddddeeeeeeeeeeee.spgm", name);
        Assert.DoesNotContain("photo", name, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("vacation", name, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Ciphertext_DoesNotContainPlaintext()
    {
        var mmk = MediaCryptography.CreateMasterKey();
        var id = Guid.NewGuid();
        var jpeg = new byte[] { 0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46 };
        jpeg = [.. jpeg, .. Enumerable.Repeat((byte)0x41, 2000)];
        using var packed = new MemoryStream();
        await MediaCryptography.EncryptAsync(new MemoryStream(jpeg), packed, MediaCryptography.FileKey(mmk, id), id, chunkSize: 1024);
        var blob = packed.ToArray();
        Assert.False(ContainsSequence(blob, [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46]));
        var otherKek = RandomNumberGenerator.GetBytes(32);
        var wrap = MediaCryptography.WrapMasterKey(RandomNumberGenerator.GetBytes(32), mmk);
        Assert.Throws<CryptographicException>(() => MediaCryptography.UnwrapMasterKey(otherKek, wrap));
    }

    private static bool ContainsSequence(byte[] haystack, byte[] needle)
    {
        if (needle.Length == 0 || haystack.Length < needle.Length)
        {
            return false;
        }

        for (var i = 0; i <= haystack.Length - needle.Length; i++)
        {
            var match = true;
            for (var j = 0; j < needle.Length; j++)
            {
                if (haystack[i + j] != needle[j])
                {
                    match = false;
                    break;
                }
            }

            if (match)
            {
                return true;
            }
        }

        return false;
    }

    [Fact]
    public void InferCategory_UsesTypeAndExtension()
    {
        Assert.Equal("photo", MediaCryptography.InferCategory("x.JPG", "image/jpeg"));
        Assert.Equal("video", MediaCryptography.InferCategory("clip.mp4", "application/octet-stream"));
        Assert.Equal("audio", MediaCryptography.InferCategory("voice.m4a", ""));
        Assert.Equal("file", MediaCryptography.InferCategory("tax.pdf", "application/pdf"));
    }
}
