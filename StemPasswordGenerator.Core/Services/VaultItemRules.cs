using StemPasswordGenerator.Models;

namespace StemPasswordGenerator.Services;

public static class VaultItemRules
{
    public const int MaximumAttachmentBytes = 8 * 1024 * 1024;

    public static bool CanSave(
        string kind,
        string title,
        string password,
        string aliasEmail,
        string cardNumber,
        string notes,
        string fullName,
        string username,
        string wifiSecurity = "")
    {
        if (string.IsNullOrWhiteSpace(title))
        {
            return false;
        }

        return kind switch
        {
            VaultItemKind.Alias => !string.IsNullOrWhiteSpace(aliasEmail),
            VaultItemKind.Card => !string.IsNullOrWhiteSpace(cardNumber),
            VaultItemKind.Note => !string.IsNullOrWhiteSpace(notes),
            VaultItemKind.Identity => !string.IsNullOrWhiteSpace(fullName) || !string.IsNullOrWhiteSpace(username),
            VaultItemKind.Recovery => !string.IsNullOrWhiteSpace(notes),
            VaultItemKind.Wifi => WifiQr.IsOpen(wifiSecurity) || !string.IsNullOrWhiteSpace(password),
            VaultItemKind.Secret => !string.IsNullOrWhiteSpace(password) || !string.IsNullOrWhiteSpace(notes),
            _ => !string.IsNullOrWhiteSpace(password) || !string.IsNullOrWhiteSpace(aliasEmail)
        };
    }

    public static int CountRecoveryCodes(string notes)
    {
        if (string.IsNullOrWhiteSpace(notes))
        {
            return 0;
        }

        var count = 0;
        var lines = notes.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries);
        for (var i = 0; i < lines.Length; i++)
        {
            if (!string.IsNullOrWhiteSpace(lines[i]))
            {
                count++;
            }
        }

        return count;
    }

    public static string AutofillUsername(string aliasEmail, string username)
    {
        return string.IsNullOrWhiteSpace(aliasEmail) ? username : aliasEmail;
    }

    public static bool IsVisible(bool value, bool invert = false) => invert ? !value : value;

    public static bool IsSealedBlob(byte[] data)
    {
        return data.Length >= 59
            && data[0] == (byte)'S'
            && data[1] == (byte)'P'
            && data[2] == (byte)'G'
            && data[3] == (byte)'1';
    }

    public static bool IsAllowedAttachmentSize(int length) =>
        length > 0 && length <= MaximumAttachmentBytes;

    public static string ContentTypeFor(string fileName)
    {
        var extension = Path.GetExtension(fileName).ToLowerInvariant();
        return extension switch
        {
            ".pdf" => "application/pdf",
            ".png" => "image/png",
            ".jpg" or ".jpeg" => "image/jpeg",
            ".webp" => "image/webp",
            ".heic" => "image/heic",
            ".txt" or ".env" or ".md" => "text/plain",
            ".json" => "application/json",
            _ => "application/octet-stream"
        };
    }
}
