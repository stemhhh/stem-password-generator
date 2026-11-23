using StemPasswordGenerator.Models;
using StemPasswordGenerator.Services;
using Xunit;

namespace StemPasswordGenerator.Tests;

public sealed class LocalIdenticonTests
{
    [Fact]
    public void Seed_UsesNormalizedHostNotTheTitle()
    {
        var item = new VaultItem
        {
            Title = "Work GitHub",
            Url = "https://www.github.com/enmanuel",
            Kind = VaultItemKind.Login
        };

        Assert.Equal("github.com", LocalIdenticon.SeedFor(item));
        Assert.Equal(LocalIdenticon.SeedFor(item), LocalIdenticon.SeedFor(VaultItemKind.Login, "https://github.com", "Other title"));
    }

    [Fact]
    public void SameDomain_SameStamp_DifferentSitesDiffer()
    {
        var github = LocalIdenticon.FromSeed("github.com");
        var again = LocalIdenticon.FromSeed("github.com");
        var gitlab = LocalIdenticon.FromSeed("gitlab.com");

        Assert.Equal(github, again);
        Assert.NotEqual(github, gitlab);
    }

    [Fact]
    public void Pattern_IsMirroredAndFilled()
    {
        var pattern = LocalIdenticon.FromSeed("netflix.com");
        var filled = 0;
        for (var row = 0; row < LocalIdenticon.GridSize; row++)
        {
            Assert.Equal(LocalIdenticon.Cell(pattern.Cells, row, 0), LocalIdenticon.Cell(pattern.Cells, row, 4));
            Assert.Equal(LocalIdenticon.Cell(pattern.Cells, row, 1), LocalIdenticon.Cell(pattern.Cells, row, 3));
            for (var column = 0; column < LocalIdenticon.GridSize; column++)
            {
                if (LocalIdenticon.Cell(pattern.Cells, row, column))
                {
                    filled++;
                }
            }
        }

        Assert.True(filled >= 4);
        Assert.Equal('N', pattern.Letter);
    }

    [Fact]
    public void WifiWithoutUrl_UsesSsid()
    {
        Assert.Equal("wifi:homenetwork", LocalIdenticon.SeedFor(VaultItemKind.Wifi, "", "HomeNetwork"));
    }
}
