using StemPasswordGenerator.Models;

namespace StemPasswordGenerator.Services;

public static class MediaGalleryRules
{
    public const string SortDateNew = "date-new";
    public const string SortDateOld = "date-old";
    public const string SortSizeLarge = "size-large";
    public const string SortSizeSmall = "size-small";
    public const string SortName = "name";
    public const string SortTag = "tag";

    public static bool IsCategory(string? category) =>
        category is MediaCategory.Photo or MediaCategory.Video or MediaCategory.Audio or MediaCategory.File;

    public static IReadOnlyList<MediaEntry> Filter(
        IEnumerable<MediaEntry> source,
        string category,
        string? folderKey,
        string? query)
    {
        ArgumentNullException.ThrowIfNull(source);
        if (!IsCategory(category))
        {
            category = MediaCategory.File;
        }

        var needle = (query ?? string.Empty).Trim();
        var list = new List<MediaEntry>();
        foreach (var entry in source)
        {
            if (!string.Equals(entry.Category, category, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (!VaultOrganizer.InFolder(entry.Folder, folderKey))
            {
                continue;
            }

            if (needle.Length > 0 && !Matches(entry, needle))
            {
                continue;
            }

            list.Add(entry);
        }

        return list;
    }

    public static IReadOnlyList<MediaEntry> Sort(IReadOnlyList<MediaEntry> items, string? sortKey)
    {
        ArgumentNullException.ThrowIfNull(items);
        var copy = items.ToList();
        copy.Sort((left, right) => Compare(left, right, sortKey));
        return copy;
    }

    public static bool Matches(MediaEntry entry, string query)
    {
        ArgumentNullException.ThrowIfNull(entry);
        return entry.Title.Contains(query, StringComparison.OrdinalIgnoreCase)
            || entry.OriginalName.Contains(query, StringComparison.OrdinalIgnoreCase)
            || entry.Category.Contains(query, StringComparison.OrdinalIgnoreCase)
            || entry.ContentType.Contains(query, StringComparison.OrdinalIgnoreCase)
            || (entry.Folder ?? string.Empty).Contains(query, StringComparison.OrdinalIgnoreCase);
    }

    private static int Compare(MediaEntry left, MediaEntry right, string? sortKey)
    {
        var result = sortKey switch
        {
            SortDateOld => left.CreatedUtc.CompareTo(right.CreatedUtc),
            SortSizeLarge => right.ByteLength.CompareTo(left.ByteLength),
            SortSizeSmall => left.ByteLength.CompareTo(right.ByteLength),
            SortName => string.Compare(DisplayName(left), DisplayName(right), StringComparison.OrdinalIgnoreCase),
            SortTag => string.Compare(
                VaultOrganizer.Normalize(left.Folder),
                VaultOrganizer.Normalize(right.Folder),
                StringComparison.OrdinalIgnoreCase),
            _ => right.CreatedUtc.CompareTo(left.CreatedUtc)
        };

        if (result != 0)
        {
            return result;
        }

        return string.Compare(DisplayName(left), DisplayName(right), StringComparison.OrdinalIgnoreCase);
    }

    private static string DisplayName(MediaEntry entry) =>
        string.IsNullOrWhiteSpace(entry.Title) ? entry.OriginalName : entry.Title;
}
