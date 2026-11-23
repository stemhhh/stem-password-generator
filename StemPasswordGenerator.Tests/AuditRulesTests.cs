using System.Text;
using StemPasswordGenerator.Models;
using StemPasswordGenerator.Services;
using Xunit;

namespace StemPasswordGenerator.Tests;

public sealed class AuditRulesTests
{
    [Fact]
    public void AuditEvent_HasNoSecretFields()
    {
        var names = typeof(AuditEvent).GetProperties().Select(property => property.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain("Password", names);
        Assert.DoesNotContain("Notes", names);
        Assert.DoesNotContain("TotpSecret", names);
        Assert.DoesNotContain("Username", names);
        Assert.DoesNotContain("CardCvv", names);
        Assert.DoesNotContain("CardNumber", names);
        Assert.Contains("Kind", names);
        Assert.Contains("Method", names);
        Assert.Contains("Utc", names);
    }

    [Fact]
    public void UnlockFail_DropsTitleAndNeverKeepsTypedMaster()
    {
        var typed = "hunter2-not-a-master-to-store";
        var cleaned = AuditRules.Sanitize(new AuditEvent
        {
            Utc = new DateTimeOffset(2026, 8, 21, 12, 0, 0, TimeSpan.Zero),
            Kind = AuditKind.UnlockFail,
            Method = AuditMethod.Master,
            Title = typed,
            ItemKind = VaultItemKind.Login,
            ItemId = Guid.NewGuid()
        });

        Assert.Equal(AuditKind.UnlockFail, cleaned.Kind);
        Assert.Equal(string.Empty, cleaned.Title);
        Assert.Equal(string.Empty, cleaned.ItemKind);
        Assert.Null(cleaned.ItemId);
        var json = Encoding.UTF8.GetString(AuditRules.ToUtf8([cleaned]));
        Assert.DoesNotContain(typed, json, StringComparison.Ordinal);
        Assert.True(AuditRules.JsonLooksSafe(Encoding.UTF8.GetBytes(json)));
    }

    [Fact]
    public void Merge_KeepsNewestWithinCap()
    {
        var events = new List<AuditEvent>();
        for (var i = 0; i < AuditRules.MaximumEvents + 25; i++)
        {
            AuditRules.Append(events, new AuditEvent
            {
                Utc = DateTimeOffset.UnixEpoch.AddMinutes(i),
                Kind = AuditKind.Created,
                Title = $"Item {i}"
            });
        }

        Assert.Equal(AuditRules.MaximumEvents, events.Count);
        Assert.Equal("Item 25", events[0].Title);
        Assert.Equal($"Item {AuditRules.MaximumEvents + 24}", events[^1].Title);
    }

    [Fact]
    public void Buckets_SplitFailUseAndEntry()
    {
        var fail = new AuditEvent { Kind = AuditKind.UnlockFail, Method = AuditMethod.Master };
        var used = new AuditEvent { Kind = AuditKind.Used, Method = AuditMethod.Copy, Title = "Bank" };
        var created = new AuditEvent { Kind = AuditKind.Created, Title = "Bank" };

        Assert.True(AuditRules.InBucket(fail, AuditBucket.Fail));
        Assert.False(AuditRules.InBucket(fail, AuditBucket.Use));
        Assert.True(AuditRules.InBucket(used, AuditBucket.Use));
        Assert.False(AuditRules.InBucket(used, AuditBucket.Entry));
        Assert.True(AuditRules.InBucket(created, AuditBucket.Entry));
        Assert.True(AuditRules.InBucket(fail, AuditBucket.All));
    }

    [Fact]
    public void Headline_DoesNotEchoASecret()
    {
        try
        {
            UiStrings.SetLanguage(AppLanguage.English);
            var row = AuditRules.Sanitize(new AuditEvent
            {
                Kind = AuditKind.UnlockFail,
                Method = AuditMethod.Master,
                Title = "super-secret-master"
            });
            var headline = AuditRules.Headline(row);
            Assert.Contains("master", headline, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("super-secret-master", headline, StringComparison.Ordinal);
        }
        finally
        {
            UiStrings.SetLanguage(AppLanguage.English);
        }
    }
}
