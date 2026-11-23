using System.Net.Http.Headers;

namespace StemPasswordGenerator.Services;

public enum HibpCheckStatus
{
    Empty,
    NotFound,
    Pwned,
    Offline
}

public readonly record struct HibpCheckResult(HibpCheckStatus Status, int Count)
{
    public static HibpCheckResult Empty { get; } = new(HibpCheckStatus.Empty, 0);

    public static HibpCheckResult Clear { get; } = new(HibpCheckStatus.NotFound, 0);

    public static HibpCheckResult Offline { get; } = new(HibpCheckStatus.Offline, 0);

    public static HibpCheckResult Hit(int count) => new(HibpCheckStatus.Pwned, Math.Max(1, count));
}

public sealed class HibpPwnedClient : IDisposable
{
    private readonly HttpClient _http;
    private readonly bool _ownsHttp;

    public HibpPwnedClient()
        : this(new HttpClient { Timeout = TimeSpan.FromSeconds(8) }, ownsHttp: true)
    {
    }

    public HibpPwnedClient(HttpMessageHandler handler, bool disposeHandler = true)
        : this(new HttpClient(handler, disposeHandler) { Timeout = TimeSpan.FromSeconds(8) }, ownsHttp: true)
    {
    }

    private HibpPwnedClient(HttpClient http, bool ownsHttp)
    {
        _http = http ?? throw new ArgumentNullException(nameof(http));
        _ownsHttp = ownsHttp;
        if (_http.DefaultRequestHeaders.UserAgent.Count == 0)
        {
            _http.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("StemPasswordGenerator", "local"));
        }
    }

    public static HibpPwnedClient Shared { get; } = new();

    public async Task<HibpCheckResult> CheckAsync(string? secret, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(secret))
        {
            return HibpCheckResult.Empty;
        }

        var hex = HibpKAnonymity.Sha1Hex(secret);
        var (prefix, suffix) = HibpKAnonymity.SplitHex(hex);
        var uri = HibpKAnonymity.RangeUri(prefix);
        if (!HibpKAnonymity.RequestIsKAnonymous(uri, secret))
        {
            return HibpCheckResult.Offline;
        }

        using var request = new HttpRequestMessage(HttpMethod.Get, uri);
        request.Headers.TryAddWithoutValidation("Add-Padding", "true");
        request.Content = null;

        try
        {
            using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
                .ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                return HibpCheckResult.Offline;
            }

            var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            var count = HibpKAnonymity.MatchCount(suffix, body);
            return count is { } hits ? HibpCheckResult.Hit(hits) : HibpCheckResult.Clear;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return HibpCheckResult.Offline;
        }
        catch (HttpRequestException)
        {
            return HibpCheckResult.Offline;
        }
        catch (TaskCanceledException)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                throw;
            }

            return HibpCheckResult.Offline;
        }
    }

    public void Dispose()
    {
        if (_ownsHttp && !ReferenceEquals(this, Shared))
        {
            _http.Dispose();
        }
    }
}
