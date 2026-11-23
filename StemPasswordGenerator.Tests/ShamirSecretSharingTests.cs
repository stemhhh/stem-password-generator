using System.Security.Cryptography;
using StemPasswordGenerator.Models;
using StemPasswordGenerator.Services;
using Xunit;

namespace StemPasswordGenerator.Tests;

public sealed class ShamirSecretSharingTests
{
    private const string Master = "correct-horse-battery";

    [Theory]
    [InlineData(0, 1)]
    [InlineData(0, 2)]
    [InlineData(1, 2)]
    public void AnyTwoCards_RecoverThePassword(int first, int second)
    {
        var cards = Split();
        var recovered = ShamirSecretSharing.CombinePassword([cards[first].Body, cards[second].Body]);
        Assert.Equal(Master, recovered);
    }

    [Fact]
    public void AllThreeCards_RecoverThePassword()
    {
        var cards = Split();
        var recovered = ShamirSecretSharing.CombinePassword([cards[0].Body, cards[1].Body, cards[2].Body]);
        Assert.Equal(Master, recovered);
    }

    [Fact]
    public void OneCard_CannotRecover()
    {
        var cards = Split();
        var error = Assert.Throws<CryptographicException>(() => ShamirSecretSharing.CombinePassword([cards[0].Body]));
        Assert.Contains("Need any 2", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void TamperedChecksum_Fails()
    {
        var cards = Split();
        var body = cards[0].Body.Replace("STEM2-1-3-", "STEM2-1-3-X", StringComparison.Ordinal);
        Assert.Throws<CryptographicException>(() => ShamirSecretSharing.CombinePassword([body, cards[1].Body]));
    }

    [Fact]
    public void Utf8Password_RoundTrips()
    {
        const string secret = "clave-maestra-ñ-12";
        var cards = ShamirSecretSharing.SplitPassword(secret, "Enmanuel", DateTimeOffset.UnixEpoch);
        var recovered = ShamirSecretSharing.CombinePassword([cards[0].Token, cards[2].Body]);
        Assert.Equal(secret, recovered);
        Assert.Contains(ShamirSecretSharing.BeginMarker, cards[0].Body, StringComparison.Ordinal);
        Assert.Contains(ShamirSecretSharing.EndMarker, cards[2].Body, StringComparison.Ordinal);
        Assert.Equal("stem-shamir-2-of-3.txt", cards[1].FileName);
    }

    [Fact]
    public void PasswordLongerThan128Utf8Bytes_Fails()
    {
        var tooLong = new string('a', 60) + new string('b', 60) + new string('c', 20);
        Assert.True(System.Text.Encoding.UTF8.GetByteCount(tooLong) > ShamirSecretSharing.MaximumSecretBytes);
        Assert.Throws<ArgumentException>(() => ShamirSecretSharing.SplitPassword(tooLong, "Alex", DateTimeOffset.UtcNow));
    }

    [Fact]
    public void SpanishCard_KeepsUnlocalizedTokenMarkers()
    {
        try
        {
            UiStrings.SetLanguage(AppLanguage.Spanish);
            var cards = Split();
            Assert.StartsWith("STEM2-1-3-", cards[0].Token, StringComparison.Ordinal);
            Assert.Contains(ShamirSecretSharing.BeginMarker, cards[0].Body, StringComparison.Ordinal);
            Assert.Contains("Tarjeta 2 de 3", cards[1].Body, StringComparison.Ordinal);
        }
        finally
        {
            UiStrings.SetLanguage(AppLanguage.English);
        }
    }

    private static IReadOnlyList<ShamirCard> Split() =>
        ShamirSecretSharing.SplitPassword(Master, "Alex", DateTimeOffset.UnixEpoch);
}
