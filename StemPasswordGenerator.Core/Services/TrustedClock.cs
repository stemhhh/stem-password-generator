namespace StemPasswordGenerator.Services;

public static class TrustedClock
{
    public static readonly TimeSpan QuorumSkew = TimeSpan.FromSeconds(45);

    public static readonly TimeSpan SingleSourceLimit = TimeSpan.FromDays(2);

    public static DateTimeOffset Bound(
        DateTimeOffset local,
        IReadOnlyList<DateTimeOffset> remotes,
        DateTimeOffset? floor)
    {
        local = AsUtc(local);
        var agreed = Agreeing(remotes);
        DateTimeOffset? remote = null;
        if (agreed.Count >= 2)
        {
            remote = Median(agreed);
        }
        else if (agreed.Count == 1 && Within(agreed[0], local, SingleSourceLimit))
        {
            remote = agreed[0];
        }

        var trusted = local;
        if (remote is { } sample && sample > trusted)
        {
            trusted = sample;
        }

        if (floor is { } stored)
        {
            stored = AsUtc(stored);
            if (stored > trusted)
            {
                trusted = stored;
            }
        }

        return trusted;
    }

    public static DateTimeOffset AsUtc(DateTimeOffset value) =>
        value.ToUniversalTime();

    public static IReadOnlyList<DateTimeOffset> Agreeing(IReadOnlyList<DateTimeOffset> remotes)
    {
        if (remotes is null || remotes.Count == 0)
        {
            return [];
        }

        var utc = remotes.Select(AsUtc).OrderBy(static value => value).ToArray();
        var median = Median(utc);
        return utc.Where(sample => Within(sample, median, QuorumSkew)).ToArray();
    }

    private static DateTimeOffset Median(IReadOnlyList<DateTimeOffset> ordered)
    {
        var mid = ordered.Count / 2;
        return ordered.Count % 2 == 1
            ? ordered[mid]
            : ordered[mid - 1].AddTicks((ordered[mid] - ordered[mid - 1]).Ticks / 2);
    }

    private static bool Within(DateTimeOffset left, DateTimeOffset right, TimeSpan window) =>
        (left - right).Duration() <= window;
}
