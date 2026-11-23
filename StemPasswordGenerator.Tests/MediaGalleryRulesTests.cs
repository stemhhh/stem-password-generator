using StemPasswordGenerator.Models;
using StemPasswordGenerator.Services;
using Xunit;

namespace StemPasswordGenerator.Tests;

public sealed class MediaGalleryRulesTests
{
    [Fact]
    public void Filter_KeepsOnlyTheRequestedCategoryAndFolder()
    {
        var items = new[]
        {
            Entry(MediaCategory.Photo, "Beach", "trip"),
            Entry(MediaCategory.Photo, "Kitchen", "home"),
            Entry(MediaCategory.Video, "Clip", "trip"),
            Entry(MediaCategory.File, "Notes", "work")
        };

        var photos = MediaGalleryRules.Filter(items, MediaCategory.Photo, "trip", query: null);
        Assert.Single(photos);
        Assert.Equal("Beach", photos[0].Title);

        var files = MediaGalleryRules.Filter(items, MediaCategory.File, VaultOrganizer.AllKey, "notes");
        Assert.Single(files);
        Assert.Equal("Notes", files[0].Title);
    }

    [Fact]
    public void Sort_OrdersByDateSizeNameAndTag()
    {
        var old = Entry(MediaCategory.File, "Alpha", "work", bytes: 10, created: DateTimeOffset.UnixEpoch);
        var newer = Entry(MediaCategory.File, "Zulu", "home", bytes: 90, created: DateTimeOffset.UnixEpoch.AddDays(2));
        var mid = Entry(MediaCategory.File, "Mike", "home", bytes: 40, created: DateTimeOffset.UnixEpoch.AddDays(1));
        var items = new[] { mid, newer, old };

        Assert.Equal(["Zulu", "Mike", "Alpha"], Names(MediaGalleryRules.Sort(items, MediaGalleryRules.SortDateNew)));
        Assert.Equal(["Alpha", "Mike", "Zulu"], Names(MediaGalleryRules.Sort(items, MediaGalleryRules.SortDateOld)));
        Assert.Equal(["Zulu", "Mike", "Alpha"], Names(MediaGalleryRules.Sort(items, MediaGalleryRules.SortSizeLarge)));
        Assert.Equal(["Alpha", "Mike", "Zulu"], Names(MediaGalleryRules.Sort(items, MediaGalleryRules.SortName)));
        Assert.Equal("home", MediaGalleryRules.Sort(items, MediaGalleryRules.SortTag)[0].Folder);
    }

    [Fact]
    public void Filter_NeverLooksOutsideTheVaultList()
    {
        var onlyVault = new[] { Entry(MediaCategory.Audio, "Song", "mix") };
        var result = MediaGalleryRules.Filter(onlyVault, MediaCategory.Audio, VaultOrganizer.AllKey, null);
        Assert.Equal(onlyVault[0].Id, result[0].Id);
        Assert.DoesNotContain(result, static item => item.OriginalName.Contains('\\') || item.OriginalName.Contains('/'));
    }

    private static MediaEntry Entry(string category, string title, string folder, long bytes = 1, DateTimeOffset? created = null)
    {
        return new MediaEntry
        {
            Category = category,
            Title = title,
            Folder = folder,
            OriginalName = title + ".bin",
            ByteLength = bytes,
            CreatedUtc = created ?? DateTimeOffset.UnixEpoch
        };
    }

    private static string[] Names(IReadOnlyList<MediaEntry> items) => items.Select(static item => item.Title).ToArray();
}
