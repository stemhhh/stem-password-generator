using System.Globalization;
using System.Net.Http.Headers;
using System.Net.Sockets;

namespace StemPasswordGenerator.Services;

public static class TrustedTimeClient
{
    public static readonly string[] NtpHosts =
    [
        "time.google.com",
        "time.cloudflare.com"
    ];

    public static readonly Uri[] HttpEndpoints =
    [
        new("https://www.google.com/generate_204"),
        new("https://www.gstatic.com/generate_204"),
        new("https://www.cloudflare.com/cdn-cgi/trace")
    ];

    public static async Task<IReadOnlyList<DateTimeOffset>> ProbeAsync(CancellationToken cancellationToken = default)
    {
        var samples = new List<DateTimeOffset>();
        var ntp = NtpHosts.Select(host => QueryNtpAsync(host, cancellationToken));
        var http = HttpEndpoints.Select(uri => QueryHttpDateAsync(uri, cancellationToken));
        var tasks = ntp.Concat(http).ToArray();
        try
        {
            await Task.WhenAll(tasks).ConfigureAwait(false);
        }
        catch (Exception)
        {
        }

        foreach (var task in tasks)
        {
            if (task.Status == TaskStatus.RanToCompletion && task.Result is { } sample)
            {
                samples.Add(sample.ToUniversalTime());
            }
        }

        return samples;
    }

    public static bool TryParseHttpDate(string? header, out DateTimeOffset utc)
    {
        utc = default;
        if (string.IsNullOrWhiteSpace(header))
        {
            return false;
        }

        if (!DateTimeOffset.TryParseExact(
                header.Trim(),
                "r",
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out utc)
            && !DateTimeOffset.TryParse(header, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out utc))
        {
            return false;
        }

        return utc.Year is >= 2020 and <= 2100;
    }

    private static async Task<DateTimeOffset?> QueryNtpAsync(string host, CancellationToken cancellationToken)
    {
        try
        {
            using var udp = new UdpClient();
            udp.Client.ReceiveTimeout = 1500;
            udp.Client.SendTimeout = 1500;
            var packet = NtpMessage.Request();
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromMilliseconds(1500));
            await udp.SendAsync(packet, packet.Length, host, 123).WaitAsync(timeout.Token).ConfigureAwait(false);
            var received = await udp.ReceiveAsync(timeout.Token).ConfigureAwait(false);
            return NtpMessage.TryParseTransmitUtc(received.Buffer, out var utc) ? utc : null;
        }
        catch (Exception)
        {
            return null;
        }
    }

    private static async Task<DateTimeOffset?> QueryHttpDateAsync(Uri uri, CancellationToken cancellationToken)
    {
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(2) };
            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            request.Headers.UserAgent.Add(new ProductInfoHeaderValue("StemPasswordGenerator", "1.9"));
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(2));
            using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token)
                .ConfigureAwait(false);
            if (response.Headers.Date is { } date)
            {
                return date.ToUniversalTime();
            }

            if (response.Headers.TryGetValues("Date", out var values))
            {
                foreach (var value in values)
                {
                    if (TryParseHttpDate(value, out var parsed))
                    {
                        return parsed;
                    }
                }
            }
        }
        catch (Exception)
        {
        }

        return null;
    }
}
