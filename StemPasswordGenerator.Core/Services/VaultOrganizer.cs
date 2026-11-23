namespace StemPasswordGenerator.Services;

public static class VaultOrganizer
{
    public const int MaximumFolderLength = 40;

    public const string AllKey = "*";

    public const string UnfiledKey = "";

    public static string Normalize(string? folder)
    {
        if (string.IsNullOrWhiteSpace(folder))
        {
            return string.Empty;
        }

        var buffer = new char[Math.Min(folder.Length, MaximumFolderLength)];
        var length = 0;
        var pendingSpace = false;
        foreach (var character in folder.Trim())
        {
            if (character is '/' or '\\' or ':' or '*' or '?' or '"' or '<' or '>' or '|')
            {
                pendingSpace = length > 0;
                continue;
            }

            if (char.IsControl(character) || char.IsWhiteSpace(character))
            {
                pendingSpace = length > 0;
                continue;
            }

            if (pendingSpace)
            {
                if (length >= buffer.Length)
                {
                    break;
                }

                buffer[length++] = ' ';
                pendingSpace = false;
            }

            if (length >= buffer.Length)
            {
                break;
            }

            buffer[length++] = character;
        }

        var normalized = new string(buffer, 0, length).Trim();
        return string.Equals(normalized, AllKey, StringComparison.Ordinal) ? string.Empty : normalized;
    }

    public static bool IsUnfiled(string? folder) => Normalize(folder).Length == 0;

    public static bool InFolder(string? itemFolder, string? filterKey)
    {
        if (filterKey is null || filterKey == AllKey)
        {
            return true;
        }

        var normalized = Normalize(itemFolder);
        if (filterKey.Length == 0)
        {
            return normalized.Length == 0;
        }

        return string.Equals(normalized, Normalize(filterKey), StringComparison.OrdinalIgnoreCase);
    }

    public static IReadOnlyList<string> DistinctFolders(IEnumerable<string?> folders)
    {
        ArgumentNullException.ThrowIfNull(folders);
        return folders
            .Select(Normalize)
            .Where(static name => name.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(static name => name, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }
}
