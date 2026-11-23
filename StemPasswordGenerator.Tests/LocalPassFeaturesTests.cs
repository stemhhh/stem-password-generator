using StemPasswordGenerator.Models;
using StemPasswordGenerator.Services;
using Xunit;

namespace StemPasswordGenerator.Tests;

public sealed class TotpServiceTests
{
    [Fact]
    public void Rfc6238_Sha1Vector()
    {
        var key = "12345678901234567890"u8.ToArray();
        Assert.Equal("287082", TotpService.GetCode(key, 59));
    }

    [Fact]
    public void ParsesOtpAuthUri()
    {
        var secret = TotpService.TryParseOtpAuth("otpauth://totp/Stem:enmanuel?secret=JBSWY3DPEHPK3PXP&issuer=Stem");
        Assert.Equal("JBSWY3DPEHPK3PXP", secret);
        Assert.False(string.IsNullOrWhiteSpace(TotpService.GetCode(secret!)));
    }
}

public sealed class AliasGeneratorTests
{
    [Fact]
    public void PlusAddress_UsesPrimaryMailbox()
    {
        var alias = AliasGenerator.Generate("you@gmail.com", string.Empty, "https://github.com");
        Assert.StartsWith("you+github.", alias);
        Assert.EndsWith("@gmail.com", alias);
    }

    [Fact]
    public void CustomDomain_IsUsed()
    {
        var alias = AliasGenerator.Generate("you@gmail.com", "alias.example.com", "netflix");
        Assert.Contains("@alias.example.com", alias);
        Assert.StartsWith("netflix.", alias);
    }
}

public sealed class VaultHealthServiceTests
{
    [Fact]
    public void DetectsReusedPasswords()
    {
        var items = new List<VaultItem>
        {
            new() { Title = "A", Password = "same-password-12", Kind = VaultItemKind.Login },
            new() { Title = "B", Password = "same-password-12", Kind = VaultItemKind.Login }
        };

        var findings = VaultHealthService.Analyze(items);
        Assert.Contains(findings, finding => finding.Detail.Contains("reused", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void PreviousPasswords_DoNotCountAsReuse()
    {
        var items = new List<VaultItem>
        {
            new()
            {
                Title = "Netflix",
                Password = "netflix-new-12",
                Kind = VaultItemKind.Login,
                PasswordHistory = [new PasswordHistoryEntry { Password = "shared-old-12" }]
            },
            new() { Title = "GitHub", Password = "shared-old-12", Kind = VaultItemKind.Login }
        };

        var findings = VaultHealthService.Analyze(items);
        Assert.DoesNotContain(findings, finding => finding.Detail.Contains("reused", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void FlagsPasswordOverOneYearOld()
    {
        var now = new DateTimeOffset(2026, 8, 21, 0, 0, 0, TimeSpan.Zero);
        var items = new List<VaultItem>
        {
            new()
            {
                Title = "Mail",
                Password = "unique-password-12",
                Kind = VaultItemKind.Login,
                TotpSecret = "JBSWY3DPEHPK3PXP",
                CreatedUtc = now.AddDays(-400),
                PasswordChangedUtc = now.AddDays(-400)
            }
        };

        var findings = VaultHealthService.Analyze(items, now);
        Assert.Contains(findings, finding => finding.Severity == "High" && finding.Detail.Contains("1 year", StringComparison.OrdinalIgnoreCase));
    }
}
