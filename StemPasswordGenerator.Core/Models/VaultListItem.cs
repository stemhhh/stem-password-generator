using StemPasswordGenerator.Services;

namespace StemPasswordGenerator.Models;

public sealed class VaultListItem
{
    public Guid Id { get; init; }

    public string Title { get; init; } = string.Empty;

    public string Username { get; init; } = string.Empty;

    public string HostLabel { get; init; } = string.Empty;

    public string KindLabel { get; init; } = UiStrings.Get("KindLogin");

    public string FolderLabel { get; init; } = string.Empty;

    public static VaultListItem From(VaultItem item)
    {
        ArgumentNullException.ThrowIfNull(item);
        return new VaultListItem
        {
            Id = item.Id,
            Title = item.Title,
            Username = Subtitle(item),
            HostLabel = item.HostLabel,
            KindLabel = item.KindLabel,
            FolderLabel = item.Folder ?? string.Empty,
            IdenticonSeed = LocalIdenticon.SeedFor(item)
        };
    }

    public string IdenticonSeed { get; init; } = string.Empty;

    public string KindAndFolder =>
        string.IsNullOrWhiteSpace(FolderLabel) ? KindLabel : KindLabel + " · " + FolderLabel;

    private static string Subtitle(VaultItem item)
    {
        if (item.Kind == VaultItemKind.Recovery)
        {
            var count = VaultItemRules.CountRecoveryCodes(item.Notes);
            return count == 0 ? item.KindLabel : UiStrings.Format("RecoveryCodeCount", count);
        }

        if (item.Kind == VaultItemKind.Wifi)
        {
            return WifiQr.NormalizeSecurity(item.WifiSecurity) switch
            {
                WifiQr.Open => UiStrings.Get("WifiOpen"),
                WifiQr.Wep => UiStrings.Get("WifiWep"),
                _ => UiStrings.Get("WifiWpa")
            };
        }

        if (item.Kind == VaultItemKind.Secret)
        {
            return string.IsNullOrWhiteSpace(item.Username) ? item.KindLabel : item.Username;
        }

        return string.IsNullOrWhiteSpace(item.AliasEmail) ? item.Username : item.AliasEmail;
    }

    public static VaultListItem From(MediaEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        var title = string.IsNullOrWhiteSpace(entry.Title) ? entry.OriginalName : entry.Title;
        return new VaultListItem
        {
            Id = entry.Id,
            Title = title,
            Username = FormatSize(entry.ByteLength),
            HostLabel = entry.OriginalName,
            KindLabel = CategoryLabel(entry.Category),
            FolderLabel = entry.Folder ?? string.Empty,
            IdenticonSeed = entry.Id.ToString("N")
        };
    }

    private static string CategoryLabel(string category) => category switch
    {
        MediaCategory.Photo => UiStrings.Get("KindPhoto"),
        MediaCategory.Video => UiStrings.Get("KindVideo"),
        MediaCategory.Audio => UiStrings.Get("KindAudio"),
        _ => UiStrings.Get("KindFile")
    };

    private static string FormatSize(long bytes)
    {
        if (bytes < 1024)
        {
            return $"{bytes} B";
        }

        if (bytes < 1024 * 1024)
        {
            return $"{bytes / 1024.0:0.#} KB";
        }

        return $"{bytes / (1024.0 * 1024):0.#} MB";
    }
}
