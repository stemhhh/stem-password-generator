using System.Security.Cryptography;
using StemPasswordGenerator.Models;
using StemPasswordGenerator.Services;
using Xunit;

namespace StemPasswordGenerator.Tests;

[Collection("FastCrypto")]
public sealed class UsbKeyCryptographyTests
{
    private const string Pin = "usb-key-pin-12";

    [Fact]
    public void StickBlob_RoundTripsTheSecret()
    {
        var secret = UsbKeyCryptography.CreateSecret();
        var blob = UsbKeyCryptography.CreateStickBlob(secret, Pin);
        var opened = UsbKeyCryptography.OpenStickBlob(blob, Pin);
        Assert.Equal(secret, opened);
        Assert.True(UsbKeyCryptography.LooksLikeStick(blob));
    }

    [Fact]
    public void WrongPin_FailsClosed()
    {
        var blob = UsbKeyCryptography.CreateStickBlob(UsbKeyCryptography.CreateSecret(), Pin);
        Assert.Throws<CryptographicException>(() => UsbKeyCryptography.OpenStickBlob(blob, "wrong-usb-pin-12"));
    }

    [Fact]
    public void Wrap_RoundTripsPackedBytes()
    {
        var secret = UsbKeyCryptography.CreateSecret();
        var packed = Enumerable.Range(1, 80).Select(static i => (byte)i).ToArray();
        var wrapped = UsbKeyCryptography.WrapPacked(packed, secret);
        Assert.Equal(packed, UsbKeyCryptography.UnwrapPacked(wrapped, secret));
    }

    [Fact]
    public void OtherSecret_CannotUnwrap()
    {
        var wrapped = UsbKeyCryptography.WrapPacked([1, 2, 3, 4, 5, 6, 7, 8], UsbKeyCryptography.CreateSecret());
        Assert.Throws<CryptographicException>(() => UsbKeyCryptography.UnwrapPacked(wrapped, UsbKeyCryptography.CreateSecret()));
    }
}

public sealed class UsbDriveRulesTests
{
    [Fact]
    public void RefusesTheSystemDrive()
    {
        Assert.False(UsbDriveRules.IsSafeLetter("C:", @"C:\"));
        Assert.False(UsbDriveRules.IsSafeLetter(@"C:\", @"C:\Windows"));
        Assert.True(UsbDriveRules.IsSafeLetter("E:", @"C:\"));
    }

    [Fact]
    public void FormatArguments_LookLikeWindowsFormat()
    {
        var args = UsbDriveRules.BuildFormatArguments(
            new UsbFormatRequest
            {
                Letter = "E:",
                FileSystem = "exfat",
                Label = "My Key!!",
                QuickFormat = true,
                ClusterBytes = 4096
            },
            @"C:\");

        Assert.Contains("E:", args, StringComparison.Ordinal);
        Assert.Contains("/FS:EXFAT", args, StringComparison.Ordinal);
        Assert.Contains("/Q", args, StringComparison.Ordinal);
        Assert.Contains("/Y", args, StringComparison.Ordinal);
        Assert.Contains("/X", args, StringComparison.Ordinal);
        Assert.Contains("/A:4K", args, StringComparison.Ordinal);
        Assert.Contains("/V:MyKey", args, StringComparison.Ordinal);
        Assert.DoesNotContain("C:", args, StringComparison.Ordinal);
    }

    [Fact]
    public void WillNotFormatSystemDrive()
    {
        Assert.Throws<InvalidOperationException>(() => UsbDriveRules.BuildFormatArguments(
            new UsbFormatRequest { Letter = "C:", FileSystem = "NTFS" },
            @"C:\"));
    }

    [Fact]
    public void LargeStick_RecommendsExFat()
    {
        Assert.True(UsbDriveRules.RecommendsExFat(64L * 1024 * 1024 * 1024));
        Assert.False(UsbDriveRules.RecommendsExFat(8L * 1024 * 1024 * 1024));
    }
}
