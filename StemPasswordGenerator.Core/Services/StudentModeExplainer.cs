using StemPasswordGenerator.Models;

namespace StemPasswordGenerator.Services;

public static class StudentModeExplainer
{
    public static StudentVaultInsight Inspect(IReadOnlyList<VaultItem>? items, string secret, string? siteUrl)
    {
        if (items is null)
        {
            return StudentVaultInsight.Locked;
        }

        var reused = new List<string>();
        var loginCount = 0;
        var missingTwoFactor = 0;
        for (var i = 0; i < items.Count; i++)
        {
            var item = items[i];
            if (PasswordMatches(item, secret))
            {
                reused.Add(DisplayTitle(item));
            }

            if (!IsLogin(item))
            {
                continue;
            }

            loginCount++;
            if (!string.IsNullOrEmpty(item.Password) && string.IsNullOrWhiteSpace(item.TotpSecret))
            {
                missingTwoFactor++;
            }
        }

        var host = string.IsNullOrWhiteSpace(siteUrl) ? null : SiteMatchService.DisplayName(siteUrl);
        var twoFactor = ResolveTwoFactor(items, siteUrl, host, loginCount, missingTwoFactor);
        return new StudentVaultInsight(true, reused, host, twoFactor, missingTwoFactor);
    }

    public static StudentModeLines Explain(double entropyBits, PasswordStrength strength, StudentVaultInsight insight)
    {
        ArgumentNullException.ThrowIfNull(insight);
        var bits = Math.Max(0, Math.Round(entropyBits)).ToString("0");
        return new StudentModeLines(
            EntropyLine(bits, strength),
            VaultLine(insight),
            TwoFactorLine(insight),
            UiStrings.Get("StudentMasterForget"));
    }

    private static string EntropyLine(string bits, PasswordStrength strength) => strength switch
    {
        PasswordStrength.Excellent => UiStrings.Format("StudentEntropyExcellent", bits),
        PasswordStrength.Strong => UiStrings.Format("StudentEntropyStrong", bits),
        PasswordStrength.Medium => UiStrings.Format("StudentEntropyMedium", bits),
        _ => UiStrings.Format("StudentEntropyWeak", bits)
    };

    private static string VaultLine(StudentVaultInsight insight)
    {
        if (!insight.VaultUnlocked)
        {
            return UiStrings.Get("StudentVaultLocked");
        }

        var titles = insight.ReusedOnTitles;
        return titles.Count switch
        {
            0 => UiStrings.Get("StudentVaultNew"),
            1 => UiStrings.Format("StudentVaultReusedOne", titles[0]),
            2 => UiStrings.Format("StudentVaultReusedTwo", titles[0], titles[1]),
            _ => UiStrings.Format("StudentVaultReusedMany", titles.Count)
        };
    }

    private static string TwoFactorLine(StudentVaultInsight insight) => insight.TwoFactor switch
    {
        StudentTwoFactor.VaultLocked => UiStrings.Get("StudentTwoFactorLocked"),
        StudentTwoFactor.EmptyVault => UiStrings.Get("StudentTwoFactorEmpty"),
        StudentTwoFactor.VaultHasGaps => UiStrings.Format("StudentTwoFactorGaps", insight.MissingTwoFactorCount),
        StudentTwoFactor.VaultAllSet => UiStrings.Get("StudentTwoFactorAllSet"),
        StudentTwoFactor.SiteNotSaved => UiStrings.Format("StudentTwoFactorSiteUnknown", insight.SiteHost ?? UiStrings.Get("ThisSite")),
        StudentTwoFactor.SiteMissing => UiStrings.Format("StudentTwoFactorSiteMissing", insight.SiteHost ?? UiStrings.Get("ThisSite")),
        StudentTwoFactor.SitePresent => UiStrings.Format("StudentTwoFactorSitePresent", insight.SiteHost ?? UiStrings.Get("ThisSite")),
        _ => UiStrings.Get("StudentTwoFactorNoSite")
    };

    private static StudentTwoFactor ResolveTwoFactor(
        IReadOnlyList<VaultItem> items,
        string? siteUrl,
        string? host,
        int loginCount,
        int missingTwoFactor)
    {
        if (!string.IsNullOrWhiteSpace(siteUrl) && !string.IsNullOrEmpty(host))
        {
            var matches = SiteMatchService.MatchForVaultInsight(items, siteUrl);
            if (matches.Count == 0)
            {
                return StudentTwoFactor.SiteNotSaved;
            }

            for (var i = 0; i < matches.Count; i++)
            {
                if (string.IsNullOrWhiteSpace(matches[i].TotpSecret))
                {
                    return StudentTwoFactor.SiteMissing;
                }
            }

            return StudentTwoFactor.SitePresent;
        }

        if (loginCount == 0)
        {
            return StudentTwoFactor.EmptyVault;
        }

        return missingTwoFactor > 0 ? StudentTwoFactor.VaultHasGaps : StudentTwoFactor.VaultAllSet;
    }

    private static bool PasswordMatches(VaultItem item, string secret)
    {
        if (string.IsNullOrEmpty(secret))
        {
            return false;
        }

        if (!string.IsNullOrEmpty(item.Password) && VaultCryptography.FixedEquals(item.Password, secret))
        {
            return true;
        }

        if (item.PasswordHistory is null)
        {
            return false;
        }

        for (var i = 0; i < item.PasswordHistory.Count; i++)
        {
            var previous = item.PasswordHistory[i].Password;
            if (!string.IsNullOrEmpty(previous) && VaultCryptography.FixedEquals(previous, secret))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsLogin(VaultItem item) => item.Kind is VaultItemKind.Login or "";

    private static string DisplayTitle(VaultItem item)
    {
        if (!string.IsNullOrWhiteSpace(item.Title))
        {
            return item.Title.Trim();
        }

        if (!string.IsNullOrWhiteSpace(item.Url))
        {
            return SiteMatchService.DisplayName(item.Url);
        }

        return UiStrings.Get("SavedLogin");
    }
}
