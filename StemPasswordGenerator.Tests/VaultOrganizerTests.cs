using StemPasswordGenerator.Services;
using Xunit;

namespace StemPasswordGenerator.Tests;

public sealed class VaultOrganizerTests
{
    [Fact]
    public void Normalize_TrimsPathJunkAndCapsLength()
    {
        Assert.Equal(string.Empty, VaultOrganizer.Normalize("  "));
        Assert.Equal("Work", VaultOrganizer.Normalize("  Work  "));
        Assert.Equal("Root Email", VaultOrganizer.Normalize("Root/Email"));
        Assert.Equal(string.Empty, VaultOrganizer.Normalize("*"));
        Assert.Equal(40, VaultOrganizer.Normalize(new string('a', 80)).Length);
    }

    [Fact]
    public void InFolder_AllUnfiledAndNamed()
    {
        Assert.True(VaultOrganizer.InFolder("Work", VaultOrganizer.AllKey));
        Assert.True(VaultOrganizer.InFolder(string.Empty, VaultOrganizer.UnfiledKey));
        Assert.False(VaultOrganizer.InFolder("Work", VaultOrganizer.UnfiledKey));
        Assert.True(VaultOrganizer.InFolder("work", "Work"));
        Assert.False(VaultOrganizer.InFolder("School", "Work"));
    }

    [Fact]
    public void DistinctFolders_SortsUniqueIgnoringCase()
    {
        var names = VaultOrganizer.DistinctFolders(["School", " work ", "Work", "", "School"]);
        Assert.Equal(["School", "work"], names);
    }
}
