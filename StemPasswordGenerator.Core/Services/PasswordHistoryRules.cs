using StemPasswordGenerator.Models;

namespace StemPasswordGenerator.Services;

public static class PasswordHistoryRules
{
    public const int MaximumEntries = 3;

    public static List<PasswordHistoryEntry> ForSave(VaultItem? existing, string newPassword, DateTimeOffset replacedUtc)
    {
        if (existing is null)
        {
            return [];
        }

        var stored = existing.PasswordHistory ?? [];
        if (string.IsNullOrEmpty(existing.Password)
            || string.Equals(existing.Password, newPassword, StringComparison.Ordinal))
        {
            return TakeNewest(stored, newPassword);
        }

        return Rotate(stored, existing.Password, newPassword, replacedUtc);
    }

    public static List<PasswordHistoryEntry> Rotate(
        IReadOnlyList<PasswordHistoryEntry>? history,
        string previousPassword,
        string newPassword,
        DateTimeOffset replacedUtc)
    {
        var next = new List<PasswordHistoryEntry>(MaximumEntries);
        if (!string.IsNullOrEmpty(previousPassword)
            && !string.Equals(previousPassword, newPassword, StringComparison.Ordinal))
        {
            next.Add(new PasswordHistoryEntry
            {
                Password = previousPassword,
                ReplacedUtc = replacedUtc
            });
        }

        AppendUnique(next, history, newPassword);
        return next;
    }

    private static List<PasswordHistoryEntry> TakeNewest(IReadOnlyList<PasswordHistoryEntry> history, string currentPassword)
    {
        var next = new List<PasswordHistoryEntry>(MaximumEntries);
        AppendUnique(next, history, currentPassword);
        return next;
    }

    private static void AppendUnique(
        List<PasswordHistoryEntry> next,
        IReadOnlyList<PasswordHistoryEntry>? history,
        string currentPassword)
    {
        if (history is null || history.Count == 0)
        {
            return;
        }

        for (var i = 0; i < history.Count && next.Count < MaximumEntries; i++)
        {
            var entry = history[i];
            if (string.IsNullOrEmpty(entry.Password)
                || string.Equals(entry.Password, currentPassword, StringComparison.Ordinal)
                || ContainsPassword(next, entry.Password))
            {
                continue;
            }

            next.Add(new PasswordHistoryEntry
            {
                Password = entry.Password,
                ReplacedUtc = entry.ReplacedUtc
            });
        }
    }

    private static bool ContainsPassword(List<PasswordHistoryEntry> entries, string password)
    {
        for (var i = 0; i < entries.Count; i++)
        {
            if (string.Equals(entries[i].Password, password, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }
}
