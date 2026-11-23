using StemPasswordGenerator.Models;
using StemPasswordGenerator.Services;
using Xunit;

namespace StemPasswordGenerator.Tests;

public sealed class SealedFileTests
{
    [Fact]
    public void Factory_CopiesBytesAndNamesTheNote()
    {
        var payload = "DATABASE_URL=postgres://localhost"u8.ToArray();
        var item = SealedFileFactory.CreateNote(@"C:\proj\.env", payload, "Sealed file");

        Assert.Equal(VaultItemKind.Note, item.Kind);
        Assert.Equal(".env", item.Title);
        Assert.Equal("Sealed file", item.Notes);
        Assert.Single(item.Attachments);
        Assert.Equal(".env", item.Attachments[0].FileName);
        Assert.Equal("text/plain", item.Attachments[0].ContentType);
        Assert.Equal("DATABASE_URL=postgres://localhost"u8.ToArray(), item.Attachments[0].Data);
        payload[0] = (byte)'x';
        Assert.NotEqual(payload[0], item.Attachments[0].Data[0]);
    }

    [Fact]
    public void Factory_RejectsEmptyAndHugeFiles()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => SealedFileFactory.CreateNote("a.pdf", [], "n"));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            SealedFileFactory.CreateNote("a.pdf", new byte[VaultItemRules.MaximumAttachmentBytes + 1], "n"));
    }

    [Fact]
    public void IsSealedBlob_DetectsSpg1Only()
    {
        var blob = new byte[64];
        blob[0] = (byte)'S';
        blob[1] = (byte)'P';
        blob[2] = (byte)'G';
        blob[3] = (byte)'1';
        Assert.True(VaultItemRules.IsSealedBlob(blob));
        blob[3] = (byte)'D';
        Assert.False(VaultItemRules.IsSealedBlob(blob));
        Assert.False(VaultItemRules.IsSealedBlob("%PDF"u8.ToArray()));
    }
}

[Collection("FastCrypto")]
public sealed class SealedFileCryptoTests
{
    private const string Master = "correct-horse-battery-staple";

    [Fact]
    public void CryptoRoundTrip_KeepsAttachmentBytes()
    {
        Argon2Profile.Use(new Argon2Profile(8 * 1024, 1, 1));
        try
        {
            var payload = Enumerable.Range(0, 32).Select(static i => (byte)i).ToArray();
            var item = SealedFileFactory.CreateNote("cedula.jpg", payload, "Sealed file");
            var crypto = new VaultCryptography();
            var blob = crypto.Encrypt(new VaultDocument { Items = [item] }, Master);
            var opened = crypto.Decrypt(blob, Master);

            Assert.Equal("cedula.jpg", opened.Items[0].Title);
            Assert.Equal(payload, opened.Items[0].Attachments[0].Data);
            Assert.Equal("image/jpeg", opened.Items[0].Attachments[0].ContentType);
            Assert.StartsWith("SPG1", System.Text.Encoding.ASCII.GetString(blob, 0, 4));
        }
        finally
        {
            Argon2Profile.ResetToMachine();
        }
    }
}
