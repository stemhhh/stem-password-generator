using StemPasswordGenerator.Services;
using Xunit;

namespace StemPasswordGenerator.Tests;

public sealed class FluidLayoutTests
{
    [Theory]
    [InlineData(300, 1)]
    [InlineData(500, 1)]
    [InlineData(736, 2)]
    [InlineData(1100, 2)]
    [InlineData(1112, 3)]
    [InlineData(1920, 3)]
    [InlineData(3840, 3)]
    public void CardColumns_GrowWithWidth_CappedAtThree(double width, int expected)
    {
        Assert.Equal(expected, FluidLayout.CardColumns(width));
    }

    [Theory]
    [InlineData(640, 1)]
    [InlineData(819, 1)]
    [InlineData(820, 2)]
    [InlineData(1379, 2)]
    [InlineData(1380, 3)]
    [InlineData(1920, 3)]
    public void GenerateColumns_MatchCompactMediumWide(double width, int expected)
    {
        Assert.Equal(expected, FluidLayout.GenerateColumns(width));
    }

    [Fact]
    public void Vault_StacksBelowEightHundred()
    {
        Assert.True(FluidLayout.IsCompactVault(640));
        Assert.False(FluidLayout.IsCompactVault(1080));
    }
}
