using StemPasswordGenerator.Services;
using Xunit;

namespace StemPasswordGenerator.Tests;

public sealed class TrustedClockTests
{
    [Fact]
    public void Bound_UsesLaterRemoteAndFloorAgainstRollback()
    {
        var local = new DateTimeOffset(2024, 8, 1, 0, 0, 0, TimeSpan.Zero);
        var remote = new DateTimeOffset(2026, 8, 21, 5, 0, 0, TimeSpan.Zero);
        var other = new DateTimeOffset(2026, 8, 21, 5, 0, 10, TimeSpan.Zero);
        var floor = new DateTimeOffset(2025, 12, 1, 0, 0, 0, TimeSpan.Zero);

        var trusted = TrustedClock.Bound(local, [remote, other], floor);
        Assert.Equal(new DateTimeOffset(2026, 8, 21, 5, 0, 5, TimeSpan.Zero), trusted);
    }

    [Fact]
    public void Bound_KeepsFloorWhenRemotesMissing()
    {
        var local = new DateTimeOffset(2024, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var floor = new DateTimeOffset(2026, 8, 1, 0, 0, 0, TimeSpan.Zero);
        Assert.Equal(floor, TrustedClock.Bound(local, [], floor));
    }

    [Fact]
    public void Bound_IgnoresLoneRemoteFarFromLocal()
    {
        var local = new DateTimeOffset(2026, 8, 21, 0, 0, 0, TimeSpan.Zero);
        var bogus = local.AddDays(30);
        Assert.Equal(local, TrustedClock.Bound(local, [bogus], null));
    }

    [Fact]
    public void NtpTransmit_RoundTrips()
    {
        var packet = new byte[NtpMessage.PacketSize];
        var utc = new DateTimeOffset(2026, 8, 21, 5, 4, 0, TimeSpan.Zero);
        NtpMessage.WriteTransmitUtc(packet, utc);
        Assert.True(NtpMessage.TryParseTransmitUtc(packet, out var parsed));
        Assert.Equal(utc.ToUnixTimeSeconds(), parsed.ToUnixTimeSeconds());
    }

    [Fact]
    public void HttpDate_ParsesRfc1123()
    {
        Assert.True(TrustedTimeClient.TryParseHttpDate("Fri, 21 Aug 2026 05:04:00 GMT", out var utc));
        Assert.Equal(2026, utc.Year);
        Assert.Equal(8, utc.Month);
        Assert.Equal(21, utc.Day);
    }
}
