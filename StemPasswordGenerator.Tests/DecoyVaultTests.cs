using StemPasswordGenerator.Models;
using StemPasswordGenerator.Services;
using Xunit;

namespace StemPasswordGenerator.Tests;

public sealed class DecoyVaultTests
{
    [Fact]
    public void SampleItems_LookLikeOrdinaryLogins()
    {
        var items = DecoyVaultSeeder.CreateSampleItems(new SecretGenerator());

        Assert.True(items.Count >= 6);
        Assert.Contains(items, item => item.Kind == VaultItemKind.Login && item.Title == "Gmail");
        Assert.Contains(items, item => item.Kind == VaultItemKind.Wifi && item.Title == "HomeNetwork");
        Assert.All(items, item => Assert.False(string.IsNullOrWhiteSpace(item.Title)));

        var logins = items.Where(item => item.Kind == VaultItemKind.Login).ToList();
        Assert.All(logins, item =>
        {
            Assert.False(string.IsNullOrWhiteSpace(item.Url));
            Assert.False(string.IsNullOrWhiteSpace(item.Username));
            Assert.True(item.Password.Length >= 12);
        });
        Assert.Equal(logins.Count, logins.Select(item => item.Password).Distinct(StringComparer.Ordinal).Count());
    }

    [Fact]
    public void PanicWarning_IsHonestAboutForensics()
    {
        UiStrings.SetLanguage(AppLanguage.English);
        Assert.Contains("quick glance", SharedPcGuidance.PanicIsNotForensics, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("undetectable", SharedPcGuidance.PanicIsNotForensics, StringComparison.OrdinalIgnoreCase);

        UiStrings.SetLanguage(AppLanguage.Spanish);
        Assert.Contains("mirada rápida", SharedPcGuidance.PanicIsNotForensics, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("forense", SharedPcGuidance.PanicIsNotForensics, StringComparison.OrdinalIgnoreCase);
        UiStrings.SetLanguage(AppLanguage.English);
    }
}
