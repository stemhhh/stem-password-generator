using System.Net;
using StemPasswordGenerator.Services;
using Xunit;

namespace StemPasswordGenerator.Tests;

public sealed class HibpKAnonymityTests
{
    private const string Password = "password";
    private const string PasswordSha1 = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8";

    [Fact]
    public void Sha1_OfPassword_MatchesPublishedVector()
    {
        Assert.Equal(PasswordSha1, HibpKAnonymity.Sha1Hex(Password));
    }

    [Fact]
    public void RangeUri_IsFiveHexPrefix_NeverTheSecretOrFullHash()
    {
        var hex = HibpKAnonymity.Sha1Hex(Password);
        var (prefix, suffix) = HibpKAnonymity.SplitHex(hex);
        var uri = HibpKAnonymity.RangeUri(prefix);

        Assert.Equal("5BAA6", prefix);
        Assert.Equal("1E4C9B93F3F0682250B6CF8331B7EE68FD8", suffix);
        Assert.True(HibpKAnonymity.RequestIsKAnonymous(uri, Password));
        Assert.Equal("/range/5BAA6", uri.AbsolutePath);
        Assert.Equal("https", uri.Scheme);
        Assert.Equal(HibpKAnonymity.RangeHost, uri.Host);
        Assert.DoesNotContain(hex, uri.AbsoluteUri, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(suffix, uri.AbsoluteUri, StringComparison.OrdinalIgnoreCase);
        Assert.False(uri.AbsolutePath.Contains(Password, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void RangeUri_ForAnInventedSecret_DoesNotEmbedTheSecret()
    {
        const string invented = "stem-unique-check-zz9";
        var hex = HibpKAnonymity.Sha1Hex(invented);
        var (prefix, suffix) = HibpKAnonymity.SplitHex(hex);
        var uri = HibpKAnonymity.RangeUri(prefix);
        Assert.True(HibpKAnonymity.RequestIsKAnonymous(uri, invented));
        Assert.DoesNotContain(invented, uri.AbsoluteUri, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(hex, uri.AbsoluteUri, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(suffix, uri.AbsoluteUri, StringComparison.OrdinalIgnoreCase);
        Assert.Equal("/range/" + prefix, uri.AbsolutePath);
    }

    [Fact]
    public void RangeUri_RejectsAPasswordAsPrefix()
    {
        Assert.Throws<ArgumentException>(() => HibpKAnonymity.RangeUri(Password));
        Assert.Throws<ArgumentException>(() => HibpKAnonymity.RangeUri(PasswordSha1));
        Assert.False(HibpKAnonymity.IsRangePrefix(Password));
        Assert.False(HibpKAnonymity.RequestIsKAnonymous(new Uri("https://api.pwnedpasswords.com/range/" + PasswordSha1), Password));
    }

    [Fact]
    public void MatchCount_IgnoresPaddingZeroAndFindsRealHits()
    {
        var body = """
            00AAA000000000000000000000000000000:0
            1E4C9B93F3F0682250B6CF8331B7EE68FD8:3303003
            FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0
            """;

        Assert.Equal(3303003, HibpKAnonymity.MatchCount("1E4C9B93F3F0682250B6CF8331B7EE68FD8", body));
        Assert.Null(HibpKAnonymity.MatchCount("00AAA000000000000000000000000000000", body));
        Assert.Null(HibpKAnonymity.MatchCount("DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEA", body));
    }

    [Fact]
    public async Task Client_SendsOnlyPrefix_WithPadding_AndNeverTheSecret()
    {
        HttpRequestMessage? seen = null;
        var handler = new StubHandler((request, _) =>
        {
            seen = request;
            Assert.True(HibpKAnonymity.RequestIsKAnonymous(request.RequestUri, Password));
            Assert.Null(request.Content);
            Assert.Equal(HttpMethod.Get, request.Method);
            Assert.True(request.Headers.TryGetValues("Add-Padding", out var padding) && padding.Contains("true"));
            var body = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:12\n";
            Assert.DoesNotContain(Password, body, StringComparison.Ordinal);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(body)
            };
        });

        using var client = new HibpPwnedClient(handler, disposeHandler: true);
        var result = await client.CheckAsync(Password);

        Assert.NotNull(seen);
        Assert.Equal(HibpCheckStatus.Pwned, result.Status);
        Assert.Equal(12, result.Count);
        Assert.Contains("/range/5BAA6", seen!.RequestUri!.AbsolutePath, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(PasswordSha1, seen.RequestUri.AbsoluteUri, StringComparison.OrdinalIgnoreCase);
        Assert.False(seen.RequestUri.AbsolutePath.Contains(Password, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Client_UnknownSuffix_IsNotFound()
    {
        var handler = new StubHandler((_, _) => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:4\n")
        });
        using var client = new HibpPwnedClient(handler, disposeHandler: true);
        var result = await client.CheckAsync("unique-stem-test-secret-zz");
        Assert.Equal(HibpCheckStatus.NotFound, result.Status);
        Assert.Equal(0, result.Count);
    }

    [Fact]
    public async Task Client_NetworkError_DoesNotThrowTheSecret()
    {
        var handler = new StubHandler((_, _) => throw new HttpRequestException("offline"));
        using var client = new HibpPwnedClient(handler, disposeHandler: true);
        var result = await client.CheckAsync(Password);
        Assert.Equal(HibpCheckStatus.Offline, result.Status);
    }

    [Fact]
    public async Task Client_ShortSecretThatAppearsInHexBody_IsStillARealResult()
    {
        var handler = new StubHandler((_, _) => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("00AAA000000000000000000000000000000:3\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0\n")
        });
        using var client = new HibpPwnedClient(handler, disposeHandler: true);
        var result = await client.CheckAsync("0");
        Assert.NotEqual(HibpCheckStatus.Offline, result.Status);
    }

    private sealed class StubHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, CancellationToken, HttpResponseMessage> _send;

        public StubHandler(Func<HttpRequestMessage, CancellationToken, HttpResponseMessage> send)
        {
            _send = send;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(_send(request, cancellationToken));
    }
}
