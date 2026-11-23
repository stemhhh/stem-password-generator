using System.Security.Cryptography;
using StemPasswordGenerator.Models;
using StemPasswordGenerator.Services;
using Xunit;

namespace StemPasswordGenerator.Tests;

[Collection("FastCrypto")]
public sealed class VaultCryptographyTests
{
    private const string Master = "correct-horse-battery-staple";

    [Fact]
    public void RoundTrip_PreservesLogins()
    {
        var crypto = new VaultCryptography();
        var document = new VaultDocument
        {
            Items =
            {
                new VaultItem
                {
                    Title = "GitHub",
                    Url = "https://github.com",
                    Username = "enmanuel",
                    Password = "s3cret!",
                    Notes = "work",
                    Folder = "School",
                    PasswordChangedUtc = new DateTimeOffset(2025, 3, 1, 0, 0, 0, TimeSpan.Zero),
                    LastUsedUtc = new DateTimeOffset(2026, 1, 15, 12, 0, 0, TimeSpan.Zero)
                }
            }
        };

        var blob = crypto.Encrypt(document, Master);
        var opened = crypto.Decrypt(blob, Master);

        Assert.Single(opened.Items);
        Assert.Equal("GitHub", opened.Items[0].Title);
        Assert.Equal("enmanuel", opened.Items[0].Username);
        Assert.Equal("s3cret!", opened.Items[0].Password);
        Assert.Equal("School", opened.Items[0].Folder);
        Assert.Equal(new DateTimeOffset(2025, 3, 1, 0, 0, 0, TimeSpan.Zero), opened.Items[0].PasswordChangedUtc);
        Assert.Equal(new DateTimeOffset(2026, 1, 15, 12, 0, 0, TimeSpan.Zero), opened.Items[0].LastUsedUtc);
        Assert.StartsWith("SPG1", System.Text.Encoding.ASCII.GetString(blob, 0, 4));
    }

    [Fact]
    public void RoundTrip_PreservesAuditWithoutSecrets()
    {
        var crypto = new VaultCryptography();
        var stamp = new DateTimeOffset(2026, 8, 21, 6, 0, 0, TimeSpan.Zero);
        var document = new VaultDocument
        {
            Items = { new VaultItem { Title = "Bank", Password = "s3cret!" } },
            Audit =
            {
                new AuditEvent
                {
                    Utc = stamp,
                    Kind = AuditKind.UnlockFail,
                    Method = AuditMethod.Master
                },
                new AuditEvent
                {
                    Utc = stamp.AddMinutes(1),
                    Kind = AuditKind.Used,
                    Method = AuditMethod.Copy,
                    Title = "Bank"
                }
            }
        };

        var opened = crypto.Decrypt(crypto.Encrypt(document, Master), Master);
        Assert.Equal(2, opened.Audit.Count);
        Assert.Equal(AuditKind.UnlockFail, opened.Audit[0].Kind);
        Assert.Equal(AuditMethod.Master, opened.Audit[0].Method);
        Assert.Equal(stamp, opened.Audit[0].Utc);
        Assert.True(string.IsNullOrEmpty(opened.Audit[0].Title));
        Assert.Equal("Bank", opened.Audit[1].Title);
        Assert.DoesNotContain("s3cret!", opened.Audit[1].Title, StringComparison.Ordinal);
    }

    [Fact]
    public void RoundTrip_PreservesMasterChangedUtc()
    {
        var crypto = new VaultCryptography();
        var stamp = new DateTimeOffset(2026, 2, 1, 8, 30, 0, TimeSpan.Zero);
        var document = new VaultDocument
        {
            Settings = { MasterChangedUtc = stamp }
        };

        var opened = crypto.Decrypt(crypto.Encrypt(document, Master), Master);

        Assert.Equal(stamp, opened.Settings.MasterChangedUtc);
    }

    [Fact]
    public void SessionKey_ReencryptsWithoutPassword()
    {
        var crypto = new VaultCryptography();
        var document = new VaultDocument
        {
            Items = { new VaultItem { Title = "App", Password = "hidden" } }
        };

        var blob = crypto.Encrypt(document, Master);
        var opened = crypto.Decrypt(blob, Master, out var key);
        using (key)
        {
            opened.Items[0].Notes = "updated";
            var again = crypto.Encrypt(opened, key);
            var third = crypto.Encrypt(opened, key);

            Assert.NotEqual(Convert.ToHexString(again), Convert.ToHexString(third));
            var roundTrip = crypto.Decrypt(again, Master);
            Assert.Equal("updated", roundTrip.Items[0].Notes);
            Assert.Equal("hidden", roundTrip.Items[0].Password);
        }
    }

    [Fact]
    public void WrongMasterPassword_Fails()
    {
        var crypto = new VaultCryptography();
        var blob = crypto.Encrypt(new VaultDocument(), Master);

        Assert.Throws<CryptographicException>(() => crypto.Decrypt(blob, "wrong-horse-battery-staple"));
    }

    [Fact]
    public void TruncatedBlob_Fails()
    {
        var crypto = new VaultCryptography();
        Assert.Throws<CryptographicException>(() => crypto.Decrypt(new byte[12], Master));
    }

    [Fact]
    public void ShortMasterPassword_IsRejected()
    {
        var crypto = new VaultCryptography();
        Assert.Throws<ArgumentException>(() => crypto.Encrypt(new VaultDocument(), "short"));
    }

    [Fact]
    public void RepetitiveMasterPassword_IsRejected()
    {
        var crypto = new VaultCryptography();
        Assert.Throws<ArgumentException>(() => crypto.Encrypt(new VaultDocument(), "aaaaaaaaaaaa"));
    }

    [Fact]
    public void Matches_AcceptsTheSessionPassword()
    {
        var crypto = new VaultCryptography();
        using var key = crypto.CreateKey(Master);
        Assert.True(VaultCryptography.Matches(Master, key));
        Assert.False(VaultCryptography.Matches("wrong-horse-battery-staple", key));
        Assert.False(VaultCryptography.Matches("short", key));
    }

    [Fact]
    public void FixedEquals_IsLengthAware()
    {
        Assert.True(VaultCryptography.FixedEquals("alpha", "alpha"));
        Assert.False(VaultCryptography.FixedEquals("alpha", "beta"));
        Assert.False(VaultCryptography.FixedEquals("alpha", "alph"));
    }
}
