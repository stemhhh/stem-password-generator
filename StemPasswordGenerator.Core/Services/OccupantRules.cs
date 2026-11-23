using StemPasswordGenerator.Models;

namespace StemPasswordGenerator.Services;

public static class OccupantRules
{
    public const int MaximumOccupants = 8;
    public const int MaximumNameLength = 40;
    public const int MaximumMailboxProfiles = 16;
    public const string DecoyFolderName = "decoy";

    public static string NormalizeName(string? name)
    {
        var trimmed = (name ?? string.Empty).Trim();
        if (trimmed.Length > MaximumNameLength)
        {
            trimmed = trimmed[..MaximumNameLength].Trim();
        }

        var cleaned = new string(trimmed.Where(static character => character is not '/' and not '\\' and not ':' and not '*' and not '?' and not '"' and not '<' and not '>' and not '|').ToArray()).Trim();
        return string.IsNullOrWhiteSpace(cleaned) ? "Person" : cleaned;
    }

    public static string FolderName(Guid id) => $"occupants\\{id:N}";

    public static bool CanAddOccupant(int count) => count < MaximumOccupants;

    public static bool CanAddMailbox(int count) => count < MaximumMailboxProfiles;

    public static bool IsSafeFolderName(string? folderName)
    {
        if (string.IsNullOrEmpty(folderName))
        {
            return true;
        }

        var normalized = folderName.Replace('/', '\\');
        if (string.Equals(normalized, DecoyFolderName, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        const string prefix = "occupants\\";
        if (normalized.Length != prefix.Length + 32 || !normalized.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var id = normalized[prefix.Length..];
        return Guid.TryParseExact(id, "N", out _);
    }

    public static string SanitizeFolderName(string? folderName, Guid occupantId)
    {
        return string.IsNullOrWhiteSpace(folderName) ? string.Empty : FolderName(occupantId);
    }
}

public static class MailboxProfileService
{
    public static void Migrate(VaultSettings settings)
    {
        settings.Profiles ??= [];
        settings.Mailboxes ??= [];

        if (settings.Profiles.Count == 0)
        {
            if (!string.IsNullOrWhiteSpace(settings.PrimaryEmail))
            {
                settings.Profiles.Add(new MailboxProfile
                {
                    Label = "Personal",
                    Email = settings.PrimaryEmail.Trim(),
                    IsDefault = true
                });
            }

            foreach (var label in settings.Mailboxes)
            {
                if (settings.Profiles.Any(profile => profile.Label.Equals(label, StringComparison.OrdinalIgnoreCase)))
                {
                    continue;
                }

                settings.Profiles.Add(new MailboxProfile
                {
                    Label = label.Trim(),
                    Email = settings.PrimaryEmail.Trim(),
                    IsDefault = settings.Profiles.Count == 0
                });
            }
        }

        if (settings.Profiles.Count > 0 && settings.Profiles.TrueForAll(profile => !profile.IsDefault))
        {
            settings.Profiles[0].IsDefault = true;
        }

        var defaultProfile = settings.Profiles.Find(profile => profile.IsDefault) ?? settings.Profiles.FirstOrDefault();
        if (defaultProfile is not null)
        {
            settings.PrimaryEmail = defaultProfile.Email;
        }

        settings.Mailboxes = settings.Profiles
            .Select(profile => profile.Label)
            .Where(static label => !string.IsNullOrWhiteSpace(label))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public static MailboxProfile? Default(IEnumerable<MailboxProfile> profiles) =>
        profiles.FirstOrDefault(profile => profile.IsDefault) ?? profiles.FirstOrDefault();
}

public static class SharedPcGuidance
{
    public static string NamesAreVisible => UiStrings.Get("WarnNamesVisible");

    public static string SharedWindowsAccount => UiStrings.Get("WarnSharedWindows");

    public static string HelloCannotTellPeopleApart => UiStrings.Get("WarnHello");

    public static string MailboxProfilesStayInside => UiStrings.Get("WarnMailboxes");

    public static string SwitchLocksMemory => UiStrings.Get("WarnSwitchLocks");

    public static string PanicIsNotForensics => UiStrings.Get("WarnPanicForensics");
}
