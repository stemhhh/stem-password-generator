using StemPasswordGenerator.Models;

namespace StemPasswordGenerator.Services;

public static class ItemUsage
{
    public static bool TracksPasswordAge(string? kind) =>
        kind is VaultItemKind.Login or VaultItemKind.Wifi or VaultItemKind.Secret or "";

    public static DateTimeOffset PasswordChangedUtc(VaultItem item)
    {
        ArgumentNullException.ThrowIfNull(item);
        return item.PasswordChangedUtc ?? item.CreatedUtc;
    }

    public static DateTimeOffset CreatedUtc(VaultItem item)
    {
        ArgumentNullException.ThrowIfNull(item);
        return item.CreatedUtc;
    }

    public static string FormatLocalDate(DateTimeOffset utc)
    {
        var culture = UiStrings.Language == AppLanguage.Spanish
            ? new System.Globalization.CultureInfo("es")
            : new System.Globalization.CultureInfo("en");
        return utc.ToLocalTime().ToString("d", culture);
    }

    public static string FormatLocalDateTime(DateTimeOffset utc)
    {
        var culture = UiStrings.Language == AppLanguage.Spanish
            ? new System.Globalization.CultureInfo("es")
            : new System.Globalization.CultureInfo("en");
        return utc.ToLocalTime().ToString("g", culture);
    }
}
