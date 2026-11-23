using StemPasswordGenerator.Models;
using StemPasswordGenerator.Services;
using Xunit;

namespace StemPasswordGenerator.Tests;

public sealed class StudentModeExplainerTests
{
    [Fact]
    public void Explain_WritesFourHumanLines()
    {
        var lines = StudentModeExplainer.Explain(96, PasswordStrength.Excellent, StudentVaultInsight.Locked);

        Assert.Contains("96", lines.Entropy, StringComparison.Ordinal);
        Assert.Contains("strong", lines.Entropy, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Unlock", lines.Vault, StringComparison.Ordinal);
        Assert.Contains("2FA", lines.TwoFactor, StringComparison.Ordinal);
        Assert.Contains("cannot invent", lines.Master, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("96", lines.Master, StringComparison.Ordinal);
    }

    [Fact]
    public void Inspect_FlagsPasswordAlreadyInTheVault()
    {
        var items = new List<VaultItem>
        {
            new() { Title = "GitHub", Password = "fresh-secret-12", Kind = VaultItemKind.Login, TotpSecret = "ABCD" },
            new() { Title = "Mail", Password = "other-secret-99", Kind = VaultItemKind.Login }
        };

        var insight = StudentModeExplainer.Inspect(items, "fresh-secret-12", null);
        var lines = StudentModeExplainer.Explain(80, PasswordStrength.Excellent, insight);

        Assert.True(insight.VaultUnlocked);
        Assert.Equal(["GitHub"], insight.ReusedOnTitles);
        Assert.Contains("GitHub", lines.Vault, StringComparison.Ordinal);
        Assert.Contains("1 saved site", lines.TwoFactor, StringComparison.Ordinal);
    }

    [Fact]
    public void Inspect_FindsPasswordInHistory()
    {
        var items = new List<VaultItem>
        {
            new()
            {
                Title = "Work",
                Password = "current-secret-12",
                Kind = VaultItemKind.Login,
                TotpSecret = "ABCD",
                PasswordHistory = [new PasswordHistoryEntry { Password = "old-secret-12" }]
            }
        };

        var insight = StudentModeExplainer.Inspect(items, "old-secret-12", "https://work.example");
        Assert.Equal(["Work"], insight.ReusedOnTitles);
        Assert.Equal(StudentTwoFactor.SitePresent, insight.TwoFactor);
    }

    [Fact]
    public void Inspect_WarnsWhenTheSiteStillHasNo2fa()
    {
        var items = new List<VaultItem>
        {
            new() { Title = "Bank", Url = "https://bank.example", Password = "vault-secret-12", Kind = VaultItemKind.Login }
        };

        var insight = StudentModeExplainer.Inspect(items, "brand-new-secret", "https://bank.example");
        var lines = StudentModeExplainer.Explain(64, PasswordStrength.Strong, insight);

        Assert.Empty(insight.ReusedOnTitles);
        Assert.Equal(StudentTwoFactor.SiteMissing, insight.TwoFactor);
        Assert.Contains("bank.example", lines.TwoFactor, StringComparison.Ordinal);
        Assert.Contains("no 2FA", lines.TwoFactor, StringComparison.Ordinal);
        Assert.Contains("not in the vault yet", lines.Vault, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void SpanishMasterLine_IsBlunt()
    {
        try
        {
            UiStrings.SetLanguage(AppLanguage.Spanish);
            var lines = StudentModeExplainer.Explain(40, PasswordStrength.Medium, StudentVaultInsight.Locked);
            Assert.Contains("no la inventa", lines.Master, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("Se acabó", lines.Master, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            UiStrings.SetLanguage(AppLanguage.English);
        }
    }
}
