using StemPasswordGenerator.Services;
using Xunit;

namespace StemPasswordGenerator.Tests;

public sealed class WifiQrTests
{
    [Fact]
    public void Payload_UsesWpaAndEscapesSpecials()
    {
        var payload = WifiQr.Payload("Cafe;Guest", @"p:a,ss\word", "WPA2");

        Assert.Equal(@"WIFI:T:WPA;S:Cafe\;Guest;P:p\:a\,ss\\word;;", payload);
    }

    [Fact]
    public void OpenNetwork_OmitsPassword()
    {
        var payload = WifiQr.Payload("Library", "ignored", "nopass");

        Assert.Equal("WIFI:T:nopass;S:Library;;", payload);
        Assert.DoesNotContain(";P:", payload, StringComparison.Ordinal);
    }

    [Fact]
    public void HiddenFlag_IsAppended()
    {
        var payload = WifiQr.Payload("Home", "secret", "WPA", hidden: true);
        Assert.Equal("WIFI:T:WPA;S:Home;P:secret;H:true;;", payload);
    }

    [Fact]
    public void QrPng_IsARealPng()
    {
        var png = QrPng.Render(WifiQr.Payload("HomeNetwork", "rivera-guest-2024", WifiQr.Wpa));
        Assert.True(QrPng.IsPng(png));
        Assert.True(png.Length > 200);
    }
}
