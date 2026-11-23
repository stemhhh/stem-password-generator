using System.Text.Json.Serialization;
using StemPasswordGenerator.Services;

namespace StemPasswordGenerator.Models;

public sealed class VaultItem
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public string Kind { get; set; } = VaultItemKind.Login;

    public string Title { get; set; } = string.Empty;

    public string Folder { get; set; } = string.Empty;

    public string Url { get; set; } = string.Empty;

    public string BrowserContainer { get; set; } = string.Empty;

    public string Username { get; set; } = string.Empty;

    public string Password { get; set; } = string.Empty;

    public string TotpSecret { get; set; } = string.Empty;

    public string AliasEmail { get; set; } = string.Empty;

    public string Mailbox { get; set; } = string.Empty;

    public string Cardholder { get; set; } = string.Empty;

    public string CardNumber { get; set; } = string.Empty;

    public string CardExpiry { get; set; } = string.Empty;

    public string CardCvv { get; set; } = string.Empty;

    public string FullName { get; set; } = string.Empty;

    public string Phone { get; set; } = string.Empty;

    public string Address { get; set; } = string.Empty;

    public string WifiSecurity { get; set; } = "WPA";

    public string Notes { get; set; } = string.Empty;

    public List<VaultAttachment> Attachments { get; set; } = [];

    public List<PasswordHistoryEntry> PasswordHistory { get; set; } = [];

    public DateTimeOffset CreatedUtc { get; set; } = DateTimeOffset.UtcNow;

    public DateTimeOffset ModifiedUtc { get; set; } = DateTimeOffset.UtcNow;

    public DateTimeOffset? PasswordChangedUtc { get; set; }

    public DateTimeOffset? LastUsedUtc { get; set; }

    [JsonIgnore]
    public string HostLabel
    {
        get
        {
            if (!string.IsNullOrWhiteSpace(AliasEmail))
            {
                return AliasEmail;
            }

            if (Uri.TryCreate(Url, UriKind.Absolute, out var uri) && !string.IsNullOrWhiteSpace(uri.Host))
            {
                return uri.Host;
            }

            return string.IsNullOrWhiteSpace(Url) ? KindLabel : Url.Trim();
        }
    }

    [JsonIgnore]
    public string KindLabel => Kind switch
    {
        VaultItemKind.Alias => UiStrings.Get("KindAlias"),
        VaultItemKind.Card => UiStrings.Get("KindCard"),
        VaultItemKind.Note => UiStrings.Get("KindNote"),
        VaultItemKind.Identity => UiStrings.Get("KindIdentity"),
        VaultItemKind.Recovery => UiStrings.Get("KindRecovery"),
        VaultItemKind.Wifi => UiStrings.Get("KindWifi"),
        VaultItemKind.Secret => UiStrings.Get("KindSecret"),
        _ => UiStrings.Get("KindLogin")
    };
}
