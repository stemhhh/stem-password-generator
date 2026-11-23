using StemPasswordGenerator.Models;

namespace StemPasswordGenerator.Services;

public static class VaultHealthService
{
    public static IReadOnlyList<HealthFinding> Analyze(IReadOnlyList<VaultItem> items, DateTimeOffset? nowUtc = null)
    {
        var findings = new List<HealthFinding>();
        var reuseCounts = new Dictionary<string, int>(StringComparer.Ordinal);
        var now = (nowUtc ?? DateTimeOffset.UtcNow).ToUniversalTime();

        for (var i = 0; i < items.Count; i++)
        {
            var item = items[i];
            if (!IsLogin(item) || string.IsNullOrEmpty(item.Password))
            {
                continue;
            }

            reuseCounts[item.Password] = reuseCounts.GetValueOrDefault(item.Password) + 1;
        }

        for (var i = 0; i < items.Count; i++)
        {
            var item = items[i];
            if (IsLogin(item) && !string.IsNullOrEmpty(item.Password))
            {
                if (reuseCounts.GetValueOrDefault(item.Password) > 1)
                {
                    findings.Add(new HealthFinding
                    {
                        ItemId = item.Id,
                        Title = item.Title,
                        Severity = "High",
                        Detail = UiStrings.Format("HealthReused", reuseCounts[item.Password])
                    });
                }

                if (item.Password.Length < 12 || UniqueCount(item.Password) < 4)
                {
                    findings.Add(new HealthFinding
                    {
                        ItemId = item.Id,
                        Title = item.Title,
                        Severity = "High",
                        Detail = UiStrings.Get("HealthWeak")
                    });
                }

                if (string.IsNullOrWhiteSpace(item.TotpSecret))
                {
                    findings.Add(new HealthFinding
                    {
                        ItemId = item.Id,
                        Title = item.Title,
                        Severity = "Medium",
                        Detail = UiStrings.Get("HealthNo2Fa")
                    });
                }
            }

            if (ItemUsage.TracksPasswordAge(item.Kind) && !string.IsNullOrEmpty(item.Password))
            {
                var changed = ItemUsage.PasswordChangedUtc(item);
                if (MasterPasswordPolicy.IsOverdue(changed, now))
                {
                    findings.Add(new HealthFinding
                    {
                        ItemId = item.Id,
                        Title = item.Title,
                        Severity = "High",
                        Detail = UiStrings.Format("HealthPasswordOverdue", ItemUsage.FormatLocalDate(changed))
                    });
                }
                else if (MasterPasswordPolicy.IsWarning(changed, now))
                {
                    findings.Add(new HealthFinding
                    {
                        ItemId = item.Id,
                        Title = item.Title,
                        Severity = "Medium",
                        Detail = UiStrings.Format(
                            "HealthPasswordSoon",
                            ItemUsage.FormatLocalDate(MasterPasswordPolicy.DueUtc(changed)))
                    });
                }
            }
        }

        findings.Sort(static (left, right) =>
        {
            var severity = Rank(left.Severity).CompareTo(Rank(right.Severity));
            return severity != 0 ? severity : string.Compare(left.Title, right.Title, StringComparison.OrdinalIgnoreCase);
        });
        return findings;
    }

    private static bool IsLogin(VaultItem item) => item.Kind is VaultItemKind.Login or "";

    private static int Rank(string severity) => severity switch { "High" => 0, "Medium" => 1, _ => 2 };

    private static int UniqueCount(string value)
    {
        var unique = new HashSet<char>(Math.Min(value.Length, 32));
        foreach (var character in value)
        {
            unique.Add(character);
        }

        return unique.Count;
    }
}
