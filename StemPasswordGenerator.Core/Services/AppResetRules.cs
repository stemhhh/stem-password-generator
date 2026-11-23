namespace StemPasswordGenerator.Services;

public static class AppResetRules
{
    public static bool CanErase(bool vaultUnlocked, bool decoySession) =>
        vaultUnlocked && !decoySession;

    public static int WarningCount => 3;

    public static bool KeepStemRootEntry(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            return false;
        }

        return name.Equals("Certificates", StringComparison.OrdinalIgnoreCase);
    }

    public static bool ShouldWipeStemRootFile(string name) =>
        name.Equals("human-skip.bin", StringComparison.OrdinalIgnoreCase);
}
