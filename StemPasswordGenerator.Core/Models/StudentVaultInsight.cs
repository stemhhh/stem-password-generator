namespace StemPasswordGenerator.Models;

public enum StudentTwoFactor
{
    VaultLocked,
    NoSite,
    EmptyVault,
    VaultHasGaps,
    VaultAllSet,
    SiteNotSaved,
    SiteMissing,
    SitePresent
}

public sealed record StudentVaultInsight(
    bool VaultUnlocked,
    IReadOnlyList<string> ReusedOnTitles,
    string? SiteHost,
    StudentTwoFactor TwoFactor,
    int MissingTwoFactorCount)
{
    public static StudentVaultInsight Locked { get; } = new(false, [], null, StudentTwoFactor.VaultLocked, 0);
}

public sealed record StudentModeLines(string Entropy, string Vault, string TwoFactor, string Master);
