using StemPasswordGenerator.Models;
using StemPasswordGenerator.Services;
using Xunit;

namespace StemPasswordGenerator.Tests;

public sealed class SecretCheckServiceTests
{
    public SecretCheckServiceTests()
    {
        UiStrings.SetLanguage(AppLanguage.English);
    }

    [Theory]
    [InlineData("password")]
    [InlineData("Password")]
    [InlineData("123456")]
    [InlineData("qwerty")]
    [InlineData("admin")]
    [InlineData("iloveyou")]
    [InlineData("contraseña")]
    [InlineData("hola123")]
    [InlineData("clave123")]
    public void CommonSecrets_AreWeak(string secret)
    {
        var report = SecretCheckService.Analyze(secret);
        Assert.Equal(PasswordStrength.Weak, report.Strength);
        Assert.Contains(UiStrings.Get("CheckFindingCommon"), report.Findings);
        Assert.True(report.EntropyBits <= 12);
    }

    [Fact]
    public void ShortPin_IsWeakAndFlagged()
    {
        var report = SecretCheckService.Analyze("1234");
        Assert.Equal(UiStrings.Get("CheckKindPin"), report.KindLabel);
        Assert.Equal(PasswordStrength.Weak, report.Strength);
        Assert.Contains(UiStrings.Get("CheckFindingShortPin"), report.Findings);
        Assert.Contains(UiStrings.Get("CheckFindingSequence"), report.Findings);
        Assert.Contains(UiStrings.Get("CheckNextPin"), report.NextSteps);
    }

    [Fact]
    public void YearPin_IsFlagged()
    {
        var report = SecretCheckService.Analyze("1998");
        Assert.Contains(UiStrings.Get("CheckFindingYear"), report.Findings);
        Assert.Equal(UiStrings.Get("CheckKindPin"), report.KindLabel);
    }

    [Fact]
    public void YearSuffix_OnShortPassword_IsFlagged()
    {
        var report = SecretCheckService.Analyze("pass2001");
        Assert.Contains(UiStrings.Get("CheckFindingYear"), report.Findings);
    }

    [Fact]
    public void RepeatedCharacters_AreFlagged()
    {
        var report = SecretCheckService.Analyze("aaaaaa");
        Assert.Contains(UiStrings.Get("CheckFindingRepeat"), report.Findings);
        Assert.Contains(UiStrings.Get("CheckFindingLowVariety"), report.Findings);
        Assert.Equal(PasswordStrength.Weak, report.Strength);
    }

    [Fact]
    public void RepeatedBlock_IsFlagged()
    {
        var report = SecretCheckService.Analyze("abcabc");
        Assert.Contains(UiStrings.Get("CheckFindingRepeat"), report.Findings);
    }

    [Theory]
    [InlineData("abcd")]
    [InlineData("xyz12345")]
    [InlineData("1qaz2wsx")]
    [InlineData("asdfghjk")]
    public void KeyboardAndNumberSequences_AreFlagged(string secret)
    {
        var report = SecretCheckService.Analyze(secret);
        Assert.Contains(UiStrings.Get("CheckFindingSequence"), report.Findings);
        Assert.True(report.Strength is PasswordStrength.Weak or PasswordStrength.Medium);
    }

    [Fact]
    public void SymbolPassword_IsNotClassifiedAsPhrase()
    {
        var report = SecretCheckService.Analyze("vK7!mQ2pL9#zR4wY");
        Assert.Equal(UiStrings.Get("CheckKindPassword"), report.KindLabel);
        Assert.DoesNotContain(UiStrings.Get("CheckFindingFewWords"), report.Findings);
    }

    [Fact]
    public void HyphenPassphrase_IsClassifiedAsPhrase()
    {
        var report = SecretCheckService.Analyze("maple-harbor-quartz-velvet");
        Assert.Equal(UiStrings.Get("CheckKindPhrase"), report.KindLabel);
    }

    [Fact]
    public void SymbolSeparatedRandomPassword_IsNotTreatedAsAGuessablePhrase()
    {
        var report = SecretCheckService.Analyze("Ab1!Cd2@Ef3#Gh4$Ij5%");
        Assert.Equal(UiStrings.Get("CheckKindPassword"), report.KindLabel);
        Assert.True(report.Strength is PasswordStrength.Strong or PasswordStrength.Excellent, report.Summary);
        Assert.True(report.EntropyBits >= 60);
        Assert.DoesNotContain(UiStrings.Get("CheckFindingGuessable"), report.Findings);
    }

    [Fact]
    public void GeneratedStrongPreset_StaysStrongAcrossManyDraws()
    {
        var workspace = new GeneratorWorkspace();
        for (var i = 0; i < 40; i++)
        {
            workspace.ApplyPreset("Strong");
            var report = SecretCheckService.Analyze(workspace.Secret);
            Assert.True(
                report.Strength is PasswordStrength.Strong or PasswordStrength.Excellent,
                $"{report.Summary} ({workspace.Secret})");
            Assert.True(report.EntropyBits >= 60, workspace.Secret);
        }
    }

    [Fact]
    public void LongMixedPassword_IsStrongOrExcellent()
    {
        var report = SecretCheckService.Analyze("vK7!mQ2pL9#zR4wY");
        Assert.True(report.Strength is PasswordStrength.Strong or PasswordStrength.Excellent);
        Assert.True(report.EntropyBits >= 60);
        Assert.Equal(UiStrings.Get("CheckKindPassword"), report.KindLabel);
        Assert.Contains(UiStrings.Get("CheckNextUnique"), report.NextSteps);
        Assert.Contains(UiStrings.Get("CheckNext2fa"), report.NextSteps);
        Assert.DoesNotContain(UiStrings.Get("CheckNextGenerate"), report.NextSteps);
    }

    [Fact]
    public void InventedShortPhrase_NeedsMoreWords()
    {
        var report = SecretCheckService.Analyze("i love you");
        Assert.Equal(UiStrings.Get("CheckKindPhrase"), report.KindLabel);
        Assert.True(report.Strength is PasswordStrength.Weak or PasswordStrength.Medium);
        Assert.Contains(UiStrings.Get("CheckFindingFewWords"), report.Findings);
        Assert.Contains(UiStrings.Get("CheckNextPhrase"), report.NextSteps);
        Assert.Contains(UiStrings.Get("CheckNextGenerate"), report.NextSteps);
    }

    [Fact]
    public void CommonWordPhrase_IsCapped()
    {
        var report = SecretCheckService.Analyze("the cat is fat");
        Assert.Equal(UiStrings.Get("CheckKindPhrase"), report.KindLabel);
        Assert.True(report.EntropyBits <= 24);
        Assert.Contains(UiStrings.Get("CheckFindingCommonPhrase"), report.Findings);
    }

    [Fact]
    public void LongerUncommonPhrase_IsStrongerThanInventedLovePhrase()
    {
        var weak = SecretCheckService.Analyze("i love you");
        var stronger = SecretCheckService.Analyze("maple-harbor-quartz-velvet-orchid-lantern");
        Assert.True(stronger.EntropyBits > weak.EntropyBits);
        Assert.True(stronger.Strength >= weak.Strength);
        Assert.Equal(UiStrings.Get("CheckKindPhrase"), stronger.KindLabel);
    }

    [Fact]
    public void SingleClassShortPassword_AsksForMixAndLength()
    {
        var report = SecretCheckService.Analyze("helloworld");
        Assert.Contains(UiStrings.Get("CheckFindingClasses"), report.Findings);
        Assert.Contains(UiStrings.Get("CheckFindingShort"), report.Findings);
        Assert.Contains(UiStrings.Get("CheckNextLength"), report.NextSteps);
        Assert.True(report.Strength is PasswordStrength.Weak or PasswordStrength.Medium);
    }

    [Fact]
    public void NullAndEmpty_ReturnEmptyReport()
    {
        Assert.Equal(SecretCheckReport.Empty, SecretCheckService.Analyze(null));
        var empty = SecretCheckService.Analyze(string.Empty);
        Assert.Equal(0, empty.EntropyBits);
        Assert.Empty(empty.Findings);
        Assert.Empty(empty.NextSteps);
        Assert.Equal(string.Empty, empty.Summary);
    }

    [Fact]
    public void VeryLongSecret_IsTruncatedWithoutThrowing()
    {
        var secret = new string('A', 400) + "z9!";
        var report = SecretCheckService.Analyze(secret);
        Assert.NotNull(report);
        Assert.True(report.EntropyBits > 0);
        Assert.Contains(UiStrings.Get("CheckFindingRepeat"), report.Findings);
    }

    [Fact]
    public void EightDigitNonSequentialPin_IsStillAPin()
    {
        var report = SecretCheckService.Analyze("48291736");
        Assert.Equal(UiStrings.Get("CheckKindPin"), report.KindLabel);
        Assert.Contains(UiStrings.Get("CheckNextPin"), report.NextSteps);
        Assert.DoesNotContain(UiStrings.Get("CheckFindingShortPin"), report.Findings);
        Assert.True(report.EntropyBits < 40);
    }

    [Fact]
    public void SpanishCommonPassword_UsesSpanishFindings()
    {
        try
        {
            UiStrings.SetLanguage(AppLanguage.Spanish);
            var report = SecretCheckService.Analyze("contraseña");
            Assert.Equal("Contraseña", report.KindLabel);
            Assert.Contains(UiStrings.Get("CheckFindingCommon"), report.Findings);
            Assert.Contains("común", report.Findings[0], StringComparison.OrdinalIgnoreCase);
            Assert.Equal("Débil", MapStrength(report.Strength));
        }
        finally
        {
            UiStrings.SetLanguage(AppLanguage.English);
        }
    }

    [Fact]
    public void SpanishTipsAndNav_StayTranslated()
    {
        try
        {
            UiStrings.SetLanguage(AppLanguage.Spanish);
            Assert.Equal("Cifrar", UiStrings.Get("NavCipher"));
            Assert.Equal("Comprobar", UiStrings.Get("NavCheck"));
            Assert.Equal("Comprobar una contraseña", UiStrings.Get("CheckTitle"));
            Assert.Contains("16+", UiStrings.Get("CheckTip1"), StringComparison.Ordinal);
            Assert.Contains("bóveda", UiStrings.Get("CheckTip5"), StringComparison.OrdinalIgnoreCase);
            Assert.Contains("k-anonimato", UiStrings.Get("CheckHibpBody"), StringComparison.OrdinalIgnoreCase);
            Assert.Contains("Have I Been Pwned", UiStrings.Get("CheckHibpButton"), StringComparison.Ordinal);
            Assert.Contains("Shamir", UiStrings.Get("CheckTip6"), StringComparison.Ordinal);
            Assert.DoesNotContain("{0}", UiStrings.Get("CheckFindingGuessable"), StringComparison.Ordinal);
        }
        finally
        {
            UiStrings.SetLanguage(AppLanguage.English);
        }
    }

    [Fact]
    public void CrackTime_ForWeakIsInstant_ForLongMixedIsYearsOrCenturies()
    {
        var weak = SecretCheckService.Analyze("1234");
        Assert.Equal(UiStrings.Get("CrackInstant"), weak.CrackTimeLabel);

        var strong = SecretCheckService.Analyze("vK7!mQ2pL9#zR4wYxB3$nT8");
        Assert.True(
            strong.CrackTimeLabel.Contains("year", StringComparison.OrdinalIgnoreCase)
            || strong.CrackTimeLabel.Contains("Centur", StringComparison.OrdinalIgnoreCase),
            strong.CrackTimeLabel);
    }

    [Fact]
    public void UnicodeLetters_DoNotCrashAndGainPool()
    {
        var ascii = SecretCheckService.Analyze("CafeLeche7!");
        var unicode = SecretCheckService.Analyze("CaféLeche7!");
        Assert.True(unicode.EntropyBits >= ascii.EntropyBits);
        Assert.Equal(UiStrings.Get("CheckKindPassword"), unicode.KindLabel);
    }

    [Fact]
    public void NextSteps_AlwaysIncludeUniqueAndTwoFactor()
    {
        foreach (var secret in new[] { "1234", "password", "i love you", "vK7!mQ2pL9#zR4wY" })
        {
            var report = SecretCheckService.Analyze(secret);
            Assert.Contains(UiStrings.Get("CheckNextUnique"), report.NextSteps);
            Assert.Contains(UiStrings.Get("CheckNext2fa"), report.NextSteps);
        }
    }

    [Fact]
    public void Findings_AreNotDuplicated()
    {
        var report = SecretCheckService.Analyze("111111");
        Assert.Equal(report.Findings.Count, report.Findings.Distinct(StringComparer.Ordinal).Count());
    }

    private static string MapStrength(PasswordStrength strength) => strength switch
    {
        PasswordStrength.Excellent => UiStrings.Get("Excellent"),
        PasswordStrength.Strong => UiStrings.Get("Strong"),
        PasswordStrength.Medium => UiStrings.Get("Medium"),
        _ => UiStrings.Get("Weak")
    };
}
