namespace StemPasswordGenerator.Services;

public static class HumanPresenceSkipRules
{
    public static readonly TimeSpan Window = TimeSpan.FromHours(1);
    public static readonly TimeSpan FutureSkew = TimeSpan.FromMinutes(2);

    public static bool AllowsSkip(DateTimeOffset? lastCompletedUtc, DateTimeOffset now)
    {
        if (lastCompletedUtc is null)
        {
            return false;
        }

        var last = lastCompletedUtc.Value;
        if (last > now.Add(FutureSkew))
        {
            return false;
        }

        return now - last < Window;
    }
}
