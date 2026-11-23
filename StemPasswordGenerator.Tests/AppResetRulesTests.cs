using StemPasswordGenerator.Services;
using Xunit;

namespace StemPasswordGenerator.Tests;

public sealed class AppResetRulesTests
{
    [Fact]
    public void CanErase_RequiresUnlockedRealVault()
    {
        Assert.True(AppResetRules.CanErase(vaultUnlocked: true, decoySession: false));
        Assert.False(AppResetRules.CanErase(vaultUnlocked: false, decoySession: false));
        Assert.False(AppResetRules.CanErase(vaultUnlocked: true, decoySession: true));
        Assert.Equal(3, AppResetRules.WarningCount);
    }

    [Fact]
    public void StemRoot_KeepsCertificates_WipesHumanSkip()
    {
        Assert.True(AppResetRules.KeepStemRootEntry("Certificates"));
        Assert.False(AppResetRules.KeepStemRootEntry("native"));
        Assert.False(AppResetRules.KeepStemRootEntry("extension"));
        Assert.False(AppResetRules.KeepStemRootEntry("packed"));
        Assert.False(AppResetRules.KeepStemRootEntry("human-skip.bin"));
        Assert.True(AppResetRules.ShouldWipeStemRootFile("human-skip.bin"));
        Assert.False(AppResetRules.ShouldWipeStemRootFile("welcome.html"));
    }
}
