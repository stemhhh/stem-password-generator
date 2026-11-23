using StemPasswordGenerator.Services;
using Xunit;

namespace StemPasswordGenerator.Tests;

public sealed class UnvirtualizedPathsTests
{
    [Fact]
    public void LocalAppData_IsTheRealUserFolderNotAPackageCache()
    {
        var path = UnvirtualizedPaths.LocalAppData();
        Assert.False(string.IsNullOrWhiteSpace(path));
        Assert.DoesNotContain(@"\Packages\", path, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(
            Path.Combine(path, "StemPasswordGenerator"),
            UnvirtualizedPaths.StemRoot());
    }
}
