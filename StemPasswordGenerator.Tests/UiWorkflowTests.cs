using StemPasswordGenerator.Models;
using StemPasswordGenerator.Services;
using Xunit;

namespace StemPasswordGenerator.Tests;

public sealed class UiWorkflowTests
{
    [Theory]
    [InlineData("Everyday")]
    [InlineData("Strong")]
    [InlineData("Extra")]
    [InlineData("WiFi")]
    [InlineData("Phrase")]
    [InlineData("PIN")]
    public void PresetButtons_ProduceUsableSecrets(string preset)
    {
        var workspace = new GeneratorWorkspace();
        Assert.True(workspace.ApplyPreset(preset));
        Assert.False(string.IsNullOrWhiteSpace(workspace.Secret));
        Assert.True(workspace.CanGenerate);
        if (preset != "PIN")
        {
            Assert.NotEqual(PasswordStrength.Weak, workspace.Strength.Strength);
        }
    }

    [Fact]
    public void EverydayPreset_OmitsSymbols_AndStartsWithLetter()
    {
        var workspace = new GeneratorWorkspace();
        workspace.ApplyPreset("Everyday");

        Assert.False(workspace.Options.IncludeSymbols);
        Assert.True(workspace.Options.BeginWithLetter);
        Assert.True(char.IsLetter(workspace.Secret[0]));
        Assert.DoesNotContain(workspace.Secret, static c => !char.IsLetterOrDigit(c));
    }

    [Fact]
    public void ExtraPreset_IsLongAndExcellent()
    {
        var workspace = new GeneratorWorkspace();
        workspace.ApplyPreset("Extra");

        Assert.Equal(32, workspace.Secret.Length);
        Assert.Equal(PasswordStrength.Excellent, workspace.Strength.Strength);
    }

    [Fact]
    public void TurningOffAllCharacterClasses_DisablesGenerate()
    {
        var workspace = new GeneratorWorkspace();
        workspace.SetOptions(PasswordOptions.CreateDefault() with
        {
            IncludeUppercase = false,
            IncludeLowercase = false,
            IncludeNumbers = false,
            IncludeSymbols = false
        });

        Assert.False(workspace.CanGenerate);
        Assert.Equal(string.Empty, workspace.Secret);
    }

    [Fact]
    public void UnknownPreset_LeavesCurrentSecret()
    {
        var workspace = new GeneratorWorkspace();
        workspace.Generate();
        var before = workspace.Secret;

        Assert.False(workspace.ApplyPreset("NotAButton"));
        Assert.Equal(before, workspace.Secret);
    }

    [Fact]
    public void History_KeepsEightMostRecent()
    {
        var workspace = new GeneratorWorkspace();
        for (var i = 0; i < 12; i++)
        {
            workspace.SetOptions(PasswordOptions.CreateDefault() with { Length = 20 + (i % 5) });
        }

        Assert.Equal(8, workspace.History.Count);
    }

    [Fact]
    public void VaultEditor_SaveRulesMatchTheForm()
    {
        Assert.False(VaultItemRules.CanSave(VaultItemKind.Login, "", "secret", "", "", "", "", ""));
        Assert.True(VaultItemRules.CanSave(VaultItemKind.Login, "GitHub", "secret", "", "", "", "", "user"));
        Assert.True(VaultItemRules.CanSave(VaultItemKind.Alias, "Netflix", "", "a+netflix@gmail.com", "", "", "", ""));
        Assert.False(VaultItemRules.CanSave(VaultItemKind.Alias, "Netflix", "", "", "", "", "", ""));
        Assert.True(VaultItemRules.CanSave(VaultItemKind.Card, "Visa", "", "", "4111111111111111", "", "", ""));
        Assert.True(VaultItemRules.CanSave(VaultItemKind.Note, "Wifi", "", "", "", "router in the closet", "", ""));
        Assert.True(VaultItemRules.CanSave(VaultItemKind.Identity, "Me", "", "", "", "", "Enmanuel", ""));
        Assert.True(VaultItemRules.CanSave(VaultItemKind.Recovery, "GitHub", "", "", "", "aaaa-bbbb\ncccc-dddd", "", ""));
        Assert.False(VaultItemRules.CanSave(VaultItemKind.Recovery, "GitHub", "", "", "", "", "", ""));
        Assert.True(VaultItemRules.CanSave(VaultItemKind.Wifi, "Home", "hunter2-long", "", "", "", "", "", WifiQr.Wpa));
        Assert.True(VaultItemRules.CanSave(VaultItemKind.Wifi, "Cafe", "", "", "", "", "", "", WifiQr.Open));
        Assert.False(VaultItemRules.CanSave(VaultItemKind.Wifi, "Home", "", "", "", "", "", "", WifiQr.Wpa));
        Assert.True(VaultItemRules.CanSave(VaultItemKind.Secret, "prod .env", "", "", "", "API_KEY=x", "", ""));
        Assert.True(VaultItemRules.CanSave(VaultItemKind.Secret, "OpenAI", "sk-test", "", "", "", "", ""));
        Assert.False(VaultItemRules.CanSave(VaultItemKind.Secret, "OpenAI", "", "", "", "", "", ""));
        Assert.Equal(2, VaultItemRules.CountRecoveryCodes("aaaa-bbbb\ncccc-dddd\n"));
    }

    [Fact]
    public void Autofill_PrefersAliasOverUsername()
    {
        Assert.Equal("hide@alias.com", VaultItemRules.AutofillUsername("hide@alias.com", "real@gmail.com"));
        Assert.Equal("real@gmail.com", VaultItemRules.AutofillUsername("", "real@gmail.com"));
    }

    [Fact]
    public void ShowHideConverters_MatchVaultPanels()
    {
        Assert.True(VaultItemRules.IsVisible(true));
        Assert.False(VaultItemRules.IsVisible(false));
        Assert.False(VaultItemRules.IsVisible(true, invert: true));
        Assert.True(VaultItemRules.IsVisible(false, invert: true));
    }

    [Fact]
    public void ProtectCenter_FlagsReusedAndMissing2fa()
    {
        var findings = VaultHealthService.Analyze(
        [
            new VaultItem { Title = "Mail", Password = "same-password-12", Kind = VaultItemKind.Login },
            new VaultItem { Title = "Work", Password = "same-password-12", Kind = VaultItemKind.Login }
        ]);

        Assert.Contains(findings, finding => finding.Detail.Contains("reused", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(findings, finding => finding.Detail.Contains("2FA", StringComparison.Ordinal));
    }

    [Fact]
    public void PhrasePreset_HasWordsAndDigit()
    {
        var workspace = new GeneratorWorkspace();
        workspace.ApplyPreset("Phrase");
        var parts = workspace.Secret.Split('-');
        Assert.Equal(7, parts.Length);
        Assert.True(char.IsDigit(parts[^1][0]));
    }

    [Fact]
    public void StrongPreset_IsTwentyCharactersWithSymbols()
    {
        var workspace = new GeneratorWorkspace();
        workspace.ApplyPreset("Strong");

        Assert.Equal(20, workspace.Secret.Length);
        Assert.True(workspace.Options.IncludeSymbols);
        Assert.Contains(workspace.Secret, static c => !char.IsLetterOrDigit(c));
    }

    [Fact]
    public void PhraseMode_CanGenerateWithoutCharacterToggles()
    {
        var workspace = new GeneratorWorkspace();
        workspace.ApplyPreset("Phrase");
        workspace.SetOptions(workspace.Options with
        {
            IncludeUppercase = false,
            IncludeLowercase = false,
            IncludeNumbers = false,
            IncludeSymbols = false
        });

        Assert.True(workspace.CanGenerate);
        Assert.False(string.IsNullOrWhiteSpace(workspace.Secret));
    }

    [Fact]
    public void WifiPreset_StartsWithALetter()
    {
        var workspace = new GeneratorWorkspace();
        workspace.ApplyPreset("WiFi");
        Assert.True(workspace.Options.BeginWithLetter);
        Assert.True(char.IsLetter(workspace.Secret[0]));
    }

    [Fact]
    public void GenerateButton_ProducesANewSecret()
    {
        var workspace = new GeneratorWorkspace();
        workspace.ApplyPreset("Strong");
        var first = workspace.Secret;
        workspace.Generate();
        Assert.NotEqual(first, workspace.Secret);
    }

    [Fact]
    public void Checker_RatesGeneratedStrongAndExtraAsStrongOrExcellent()
    {
        var workspace = new GeneratorWorkspace();
        workspace.ApplyPreset("Strong");
        var strong = SecretCheckService.Analyze(workspace.Secret);
        Assert.True(strong.Strength is PasswordStrength.Strong or PasswordStrength.Excellent, strong.Summary);
        Assert.True(strong.EntropyBits >= 60);

        workspace.ApplyPreset("Extra");
        var extra = SecretCheckService.Analyze(workspace.Secret);
        Assert.Equal(PasswordStrength.Excellent, extra.Strength);
        Assert.DoesNotContain(UiStrings.Get("CheckFindingCommon"), extra.Findings);
    }

    [Fact]
    public void Checker_RatesGeneratedFourDigitPinAsWeak()
    {
        var workspace = new GeneratorWorkspace();
        workspace.ApplyPreset("PIN");
        workspace.SetOptions(workspace.Options with { Mode = GeneratorMode.Pin, Length = 4 });
        var report = SecretCheckService.Analyze(workspace.Secret);
        Assert.Equal(UiStrings.Get("CheckKindPin"), report.KindLabel);
        Assert.True(report.Strength is PasswordStrength.Weak or PasswordStrength.Medium);
        Assert.Contains(UiStrings.Get("CheckNextPin"), report.NextSteps);
    }

    [Fact]
    public void Checker_RatesGeneratedPassphraseAboveInventedPhrase()
    {
        var workspace = new GeneratorWorkspace();
        workspace.ApplyPreset("Phrase");
        var generated = SecretCheckService.Analyze(workspace.Secret);
        var invented = SecretCheckService.Analyze("i love you");
        Assert.True(generated.EntropyBits > invented.EntropyBits);
        Assert.True(generated.Strength >= PasswordStrength.Medium);
    }

    [Fact]
    public void CheckerAdviceCatalog_HasSixTipsInBothLanguages()
    {
        try
        {
            for (var i = 1; i <= 6; i++)
            {
                UiStrings.SetLanguage(AppLanguage.English);
                var english = UiStrings.Get("CheckTip" + i);
                UiStrings.SetLanguage(AppLanguage.Spanish);
                var spanish = UiStrings.Get("CheckTip" + i);
                Assert.False(string.IsNullOrWhiteSpace(english));
                Assert.False(string.IsNullOrWhiteSpace(spanish));
                Assert.NotEqual(english, spanish);
            }
        }
        finally
        {
            UiStrings.SetLanguage(AppLanguage.English);
        }
    }
}
