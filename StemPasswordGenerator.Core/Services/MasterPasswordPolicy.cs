namespace StemPasswordGenerator.Services;

public static class MasterPasswordPolicy
{
    public const int LifetimeDays = 365;
    public const int WarningDays = 30;

    public static DateTimeOffset DueUtc(DateTimeOffset changedUtc) => changedUtc.AddDays(LifetimeDays);

    public static int DaysRemaining(DateTimeOffset changedUtc, DateTimeOffset now) =>
        (int)Math.Ceiling((DueUtc(changedUtc) - now).TotalDays);

    public static bool IsOverdue(DateTimeOffset changedUtc, DateTimeOffset now) =>
        now >= DueUtc(changedUtc);

    public static bool IsWarning(DateTimeOffset changedUtc, DateTimeOffset now)
    {
        var remaining = DaysRemaining(changedUtc, now);
        return remaining > 0 && remaining <= WarningDays;
    }
}
