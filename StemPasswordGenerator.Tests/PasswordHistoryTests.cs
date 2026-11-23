using StemPasswordGenerator.Models;
using StemPasswordGenerator.Services;
using Xunit;

namespace StemPasswordGenerator.Tests;

public sealed class PasswordHistoryTests
{
    [Fact]
    public void NewItem_HasNoHistory()
    {
        var history = PasswordHistoryRules.ForSave(null, "fresh-password", DateTimeOffset.UtcNow);
        Assert.Empty(history);
    }

    [Fact]
    public void SamePassword_KeepsExistingHistory()
    {
        var replaced = DateTimeOffset.Parse("2026-08-01T00:00:00Z");
        var item = new VaultItem
        {
            Password = "current-one",
            PasswordHistory =
            [
                new PasswordHistoryEntry { Password = "old-one", ReplacedUtc = replaced }
            ]
        };

        var history = PasswordHistoryRules.ForSave(item, "current-one", DateTimeOffset.UtcNow);

        Assert.Single(history);
        Assert.Equal("old-one", history[0].Password);
        Assert.Equal(replaced, history[0].ReplacedUtc);
    }

    [Fact]
    public void Rotate_KeepsPreviousEncryptedSlot()
    {
        var now = DateTimeOffset.Parse("2026-08-20T12:00:00Z");
        var item = new VaultItem { Password = "netflix-old" };

        var history = PasswordHistoryRules.ForSave(item, "netflix-new", now);

        Assert.Single(history);
        Assert.Equal("netflix-old", history[0].Password);
        Assert.Equal(now, history[0].ReplacedUtc);
    }

    [Fact]
    public void Rotate_KeepsOnlyTheLastThree()
    {
        var item = new VaultItem { Password = "p1" };
        var t1 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var history = PasswordHistoryRules.ForSave(item, "p2", t1);
        item = new VaultItem { Password = "p2", PasswordHistory = history };
        history = PasswordHistoryRules.ForSave(item, "p3", t1.AddDays(1));
        item = new VaultItem { Password = "p3", PasswordHistory = history };
        history = PasswordHistoryRules.ForSave(item, "p4", t1.AddDays(2));
        item = new VaultItem { Password = "p4", PasswordHistory = history };
        history = PasswordHistoryRules.ForSave(item, "p5", t1.AddDays(3));

        Assert.Equal(3, history.Count);
        Assert.Equal(["p4", "p3", "p2"], history.Select(entry => entry.Password).ToArray());
        Assert.DoesNotContain(history, entry => entry.Password == "p1");
    }

    [Fact]
    public void RotateBack_DropsTheRestoredPasswordFromHistory()
    {
        var item = new VaultItem
        {
            Password = "new-one",
            PasswordHistory =
            [
                new PasswordHistoryEntry { Password = "old-one", ReplacedUtc = DateTimeOffset.UtcNow }
            ]
        };

        var history = PasswordHistoryRules.ForSave(item, "old-one", DateTimeOffset.UtcNow);

        Assert.Single(history);
        Assert.Equal("new-one", history[0].Password);
        Assert.DoesNotContain(history, entry => entry.Password == "old-one");
    }

    [Fact]
    public void EmptyPrevious_IsNotRecorded()
    {
        var item = new VaultItem { Password = string.Empty };
        var history = PasswordHistoryRules.ForSave(item, "first-secret", DateTimeOffset.UtcNow);
        Assert.Empty(history);
    }
}

[Collection("FastCrypto")]
public sealed class PasswordHistoryCryptoTests
{
    private const string Master = "correct-horse-battery-staple";

    [Fact]
    public void RoundTrip_KeepsPreviousPasswordsInsideTheVaultBlob()
    {
        Argon2Profile.Use(new Argon2Profile(8 * 1024, 1, 1));
        try
        {
            var replaced = DateTimeOffset.Parse("2026-08-18T15:00:00Z");
            var document = new VaultDocument
            {
                Items =
                {
                    new VaultItem
                    {
                        Title = "Netflix",
                        Password = "current-secret",
                        PasswordHistory =
                        [
                            new PasswordHistoryEntry { Password = "old-secret-1", ReplacedUtc = replaced },
                            new PasswordHistoryEntry { Password = "old-secret-2", ReplacedUtc = replaced.AddDays(-7) }
                        ]
                    }
                }
            };

            var crypto = new VaultCryptography();
            var blob = crypto.Encrypt(document, Master);
            var opened = crypto.Decrypt(blob, Master);

            Assert.Equal("current-secret", opened.Items[0].Password);
            Assert.Equal(2, opened.Items[0].PasswordHistory.Count);
            Assert.Equal("old-secret-1", opened.Items[0].PasswordHistory[0].Password);
            Assert.Equal("old-secret-2", opened.Items[0].PasswordHistory[1].Password);
            Assert.Equal(replaced, opened.Items[0].PasswordHistory[0].ReplacedUtc);
            Assert.StartsWith("SPG1", System.Text.Encoding.ASCII.GetString(blob, 0, 4));
        }
        finally
        {
            Argon2Profile.ResetToMachine();
        }
    }
}
