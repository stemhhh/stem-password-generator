using StemPasswordGenerator.Services;
using Xunit;

namespace StemPasswordGenerator.Tests;

public sealed class HumanPresenceSkipRulesTests
{
    [Fact]
    public void AllowsSkip_OncePerHourThenAsksAgain()
    {
        var start = new DateTimeOffset(2026, 8, 21, 16, 0, 0, TimeSpan.Zero);
        Assert.False(HumanPresenceSkipRules.AllowsSkip(null, start));
        Assert.True(HumanPresenceSkipRules.AllowsSkip(start, start.AddMinutes(59)));
        Assert.False(HumanPresenceSkipRules.AllowsSkip(start, start.AddHours(1)));
        Assert.False(HumanPresenceSkipRules.AllowsSkip(start.AddHours(3), start));
    }
}
