using System.Security.Cryptography;
using StemPasswordGenerator.Services;
using Xunit;

namespace StemPasswordGenerator.Tests;

public sealed class KeePassKdbxImporterTests
{
    private static readonly KeePassKdbxTestFactory.SampleEntry Sample = new(
        "GitHub",
        "enmanuel",
        "kdbx-secret!",
        "https://github.com",
        "from keepass",
        "otpauth://totp/GitHub:enmanuel?secret=JBSWY3DPEHPK3PXP");

    [Fact]
    public void LooksLike_RequiresSignature()
    {
        Assert.False(KeePassKdbxImporter.LooksLike("name,url,username,password\n"u8.ToArray()));
        Assert.True(KeePassKdbxImporter.LooksLike(KeePassKdbxTestFactory.WriteV3("pw-12-chars", Sample)));
    }

    [Fact]
    public void Kdbx3_RoundTrip_WithProtectedPassword()
    {
        var data = KeePassKdbxTestFactory.WriteV3("correct horse", Sample, protectPassword: true);
        var result = KeePassKdbxImporter.Open(data, "correct horse");

        Assert.True(result.Success, result.ErrorKey);
        Assert.Equal("keepass-kdbx", result.Format);
        Assert.Equal("GitHub", result.Items[0].Title);
        Assert.Equal("enmanuel", result.Items[0].Username);
        Assert.Equal("kdbx-secret!", result.Items[0].Password);
        Assert.Equal("https://github.com", result.Items[0].Url);
        Assert.Equal("from keepass", result.Items[0].Notes);
        Assert.Equal("JBSWY3DPEHPK3PXP", result.Items[0].TotpSecret);
        Assert.DoesNotContain(result.Items, item => item.Title == "Trashed");
    }

    [Fact]
    public void Kdbx4_AesKdf_RoundTrip()
    {
        var data = KeePassKdbxTestFactory.WriteV4("another horse", Sample, argon2: false);
        var result = KeePassKdbxImporter.Open(data, "another horse");

        Assert.True(result.Success, result.ErrorKey);
        Assert.Equal("kdbx-secret!", result.Items[0].Password);
        Assert.Equal("JBSWY3DPEHPK3PXP", result.Items[0].TotpSecret);
    }

    [Fact]
    public void Kdbx4_Argon2id_RoundTrip()
    {
        var data = KeePassKdbxTestFactory.WriteV4("argon2-horse", Sample, argon2: true);
        var result = KeePassKdbxImporter.Open(data, "argon2-horse");

        Assert.True(result.Success, result.ErrorKey);
        Assert.Equal("GitHub", result.Items[0].Title);
        Assert.Equal("kdbx-secret!", result.Items[0].Password);
    }

    [Fact]
    public void WrongPassword_FailsClosed()
    {
        var data = KeePassKdbxTestFactory.WriteV3("right-password", Sample);
        var result = KeePassKdbxImporter.Open(data, "wrong-password");
        Assert.False(result.Success);
        Assert.Equal("KeePassWrongPassword", result.ErrorKey);
    }

    [Fact]
    public void EmptyPassword_FailsClosed()
    {
        var data = KeePassKdbxTestFactory.WriteV3("right-password", Sample);
        Assert.Equal("KeePassNeedPassword", KeePassKdbxImporter.Open(data, "").ErrorKey);
    }

    [Fact]
    public void Salsa20_IsAnInvolution()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var nonce = RandomNumberGenerator.GetBytes(8);
        var original = "keepass-inner-stream"u8.ToArray();
        var once = KeePassStreamCipher.Salsa20(key, nonce, original);
        var twice = KeePassStreamCipher.Salsa20(key, nonce, once);
        Assert.Equal(original, twice);
    }
}
