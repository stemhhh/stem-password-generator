using StemPasswordGenerator.Services;
using Xunit;

namespace StemPasswordGenerator.Tests;

public sealed class MasterPasswordPolicyTests
{
    [Fact]
    public void Lifetime_IsOneYear()
    {
        var changed = new DateTimeOffset(2025, 3, 1, 12, 0, 0, TimeSpan.Zero);
        Assert.Equal(changed.AddDays(365), MasterPasswordPolicy.DueUtc(changed));
        Assert.Equal(365, MasterPasswordPolicy.LifetimeDays);
        Assert.Equal(30, MasterPasswordPolicy.WarningDays);
    }

    [Fact]
    public void Overdue_After365Days()
    {
        var changed = new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero);
        Assert.False(MasterPasswordPolicy.IsOverdue(changed, changed.AddDays(364)));
        Assert.True(MasterPasswordPolicy.IsOverdue(changed, changed.AddDays(365)));
        Assert.True(MasterPasswordPolicy.IsOverdue(changed, changed.AddDays(400)));
    }

    [Fact]
    public void Warning_Last30Days()
    {
        var changed = new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero);
        Assert.False(MasterPasswordPolicy.IsWarning(changed, changed.AddDays(300)));
        Assert.True(MasterPasswordPolicy.IsWarning(changed, changed.AddDays(335)));
        Assert.True(MasterPasswordPolicy.IsWarning(changed, changed.AddDays(364)));
        Assert.False(MasterPasswordPolicy.IsWarning(changed, changed.AddDays(365)));
    }

    [Fact]
    public void DaysRemaining_RoundsUp()
    {
        var changed = new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero);
        Assert.Equal(10, MasterPasswordPolicy.DaysRemaining(changed, changed.AddDays(355)));
        Assert.Equal(0, MasterPasswordPolicy.DaysRemaining(changed, changed.AddDays(365)));
        Assert.True(MasterPasswordPolicy.DaysRemaining(changed, changed.AddDays(400)) < 0);
    }
}
