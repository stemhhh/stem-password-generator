using System.Security.Cryptography;
using System.Text;
using StemPasswordGenerator.Models;

namespace StemPasswordGenerator.Services;

public sealed class CsvVaultExportResult
{
    public byte[] Data { get; init; } = [];

    public int Written { get; init; }

    public int Skipped { get; init; }

    public string? ErrorKey { get; init; }

    public object[] ErrorArgs { get; init; } = [];

    public bool Success => ErrorKey is null && Data.Length > 0;

    public static CsvVaultExportResult Fail(string key, params object[] args) => new()
    {
        ErrorKey = key,
        ErrorArgs = args
    };
}

public static class CsvVaultExporter
{
    internal static readonly string[] Header =
    [
        "name",
        "url",
        "username",
        "password",
        "note",
        "folder",
        "favorite",
        "type",
        "notes",
        "fields",
        "reprompt",
        "login_uri",
        "login_username",
        "login_password",
        "login_totp",
        "card_cardholderName",
        "card_number",
        "card_expMonth",
        "card_expYear",
        "card_code",
        "identity_firstName",
        "identity_lastName",
        "identity_address1",
        "identity_email",
        "identity_phone",
        "identity_username"
    ];

    public static CsvVaultExportResult Write(IEnumerable<VaultItem> items)
    {
        ArgumentNullException.ThrowIfNull(items);
        var rows = new List<string[]>();
        var skipped = 0;
        foreach (var item in items)
        {
            if (item is null)
            {
                skipped++;
                continue;
            }

            var row = ToRow(item);
            if (row is null)
            {
                skipped++;
                continue;
            }

            rows.Add(row);
        }

        if (rows.Count == 0)
        {
            return CsvVaultExportResult.Fail("CsvExportEmpty");
        }

        var csv = new StringBuilder();
        AppendRow(csv, Header);
        for (var i = 0; i < rows.Count; i++)
        {
            AppendRow(csv, rows[i]);
        }

        var payload = Encoding.UTF8.GetBytes(csv.ToString());
        var data = new byte[Encoding.UTF8.Preamble.Length + payload.Length];
        Buffer.BlockCopy(Encoding.UTF8.GetPreamble(), 0, data, 0, Encoding.UTF8.Preamble.Length);
        Buffer.BlockCopy(payload, 0, data, Encoding.UTF8.Preamble.Length, payload.Length);
        if (data.Length > CsvVaultImporter.MaximumBytes)
        {
            CryptographicOperations.ZeroMemory(payload);
            CryptographicOperations.ZeroMemory(data);
            return CsvVaultExportResult.Fail("CsvTooLarge", CsvVaultImporter.MaximumBytes / (1024 * 1024));
        }

        CryptographicOperations.ZeroMemory(payload);
        return new CsvVaultExportResult
        {
            Data = data,
            Written = rows.Count,
            Skipped = skipped
        };
    }

    private static string[]? ToRow(VaultItem item)
    {
        var row = new string[Header.Length];
        Array.Fill(row, string.Empty);
        Set(row, "folder", VaultOrganizer.Normalize(item.Folder));
        var kind = item.Kind ?? string.Empty;
        if (kind is VaultItemKind.Card)
        {
            if (string.IsNullOrWhiteSpace(item.CardNumber))
            {
                return null;
            }

            Set(row, "type", "card");
            Set(row, "name", TitleOr(item.Title, UiStrings.Get("KindCard")));
            Set(row, "notes", item.Notes);
            Set(row, "note", item.Notes);
            Set(row, "card_cardholderName", item.Cardholder);
            Set(row, "card_number", item.CardNumber);
            var (month, year) = SplitExpiry(item.CardExpiry);
            Set(row, "card_expMonth", month);
            Set(row, "card_expYear", year);
            Set(row, "card_code", item.CardCvv);
            return row;
        }

        if (kind is VaultItemKind.Identity)
        {
            if (string.IsNullOrWhiteSpace(item.FullName) && string.IsNullOrWhiteSpace(item.Username))
            {
                return null;
            }

            var (first, last) = SplitName(item.FullName);
            Set(row, "type", "identity");
            Set(row, "name", TitleOr(item.Title, item.FullName));
            Set(row, "notes", item.Notes);
            Set(row, "note", item.Notes);
            Set(row, "identity_firstName", first);
            Set(row, "identity_lastName", last);
            Set(row, "identity_address1", item.Address);
            Set(row, "identity_phone", item.Phone);
            if (LooksLikeEmail(item.Username))
            {
                Set(row, "identity_email", item.Username);
            }
            else
            {
                Set(row, "identity_username", item.Username);
            }

            return row;
        }

        if (kind is VaultItemKind.Note or VaultItemKind.Recovery
            || (kind is VaultItemKind.Secret or VaultItemKind.Wifi
                && string.IsNullOrWhiteSpace(item.Password)
                && string.IsNullOrWhiteSpace(item.TotpSecret)))
        {
            var notes = NoteBody(item);
            if (string.IsNullOrWhiteSpace(item.Title) && string.IsNullOrWhiteSpace(notes))
            {
                return null;
            }

            Set(row, "type", "note");
            Set(row, "name", TitleOr(item.Title, UiStrings.Get("KindNote")));
            Set(row, "notes", notes);
            Set(row, "note", notes);
            return row;
        }

        var username = FirstNonEmpty(item.Username, item.AliasEmail);
        var password = item.Password ?? string.Empty;
        var totp = item.TotpSecret ?? string.Empty;
        if (string.IsNullOrWhiteSpace(password) && string.IsNullOrWhiteSpace(totp))
        {
            return null;
        }

        var url = item.Url ?? string.Empty;
        var loginNotes = LoginNotes(item);
        Set(row, "type", "login");
        Set(row, "name", TitleOr(item.Title, url));
        Set(row, "url", url);
        Set(row, "username", username);
        Set(row, "password", password);
        Set(row, "note", loginNotes);
        Set(row, "notes", loginNotes);
        Set(row, "login_uri", url);
        Set(row, "login_username", username);
        Set(row, "login_password", password);
        Set(row, "login_totp", totp);
        return row;
    }

    private static string LoginNotes(VaultItem item)
    {
        if (item.Kind is VaultItemKind.Wifi && !string.IsNullOrWhiteSpace(item.WifiSecurity))
        {
            return string.IsNullOrWhiteSpace(item.Notes)
                ? item.WifiSecurity
                : item.Notes.Trim() + Environment.NewLine + item.WifiSecurity;
        }

        return item.Notes ?? string.Empty;
    }

    private static string NoteBody(VaultItem item)
    {
        if (item.Kind is VaultItemKind.Wifi && !string.IsNullOrWhiteSpace(item.WifiSecurity))
        {
            return string.IsNullOrWhiteSpace(item.Notes)
                ? item.WifiSecurity
                : item.Notes.Trim() + Environment.NewLine + item.WifiSecurity;
        }

        if (item.Kind is VaultItemKind.Secret && !string.IsNullOrWhiteSpace(item.Password))
        {
            return item.Notes ?? string.Empty;
        }

        return item.Notes ?? string.Empty;
    }

    private static string TitleOr(string title, string fallback)
    {
        var trimmed = (title ?? string.Empty).Trim();
        if (trimmed.Length > 0)
        {
            return trimmed;
        }

        var host = SiteMatchService.DisplayName(fallback);
        if (host.Length > 0)
        {
            return host;
        }

        trimmed = (fallback ?? string.Empty).Trim();
        return trimmed.Length > 0 ? trimmed : UiStrings.Get("ImportedLoginTitle");
    }

    private static (string Month, string Year) SplitExpiry(string expiry)
    {
        var trimmed = (expiry ?? string.Empty).Trim();
        if (trimmed.Length == 0)
        {
            return (string.Empty, string.Empty);
        }

        var slash = trimmed.IndexOf('/');
        if (slash <= 0 || slash == trimmed.Length - 1)
        {
            return (trimmed, string.Empty);
        }

        return (trimmed[..slash].Trim(), trimmed[(slash + 1)..].Trim());
    }

    private static (string First, string Last) SplitName(string fullName)
    {
        var trimmed = (fullName ?? string.Empty).Trim();
        if (trimmed.Length == 0)
        {
            return (string.Empty, string.Empty);
        }

        var space = trimmed.IndexOf(' ');
        return space < 0 ? (trimmed, string.Empty) : (trimmed[..space], trimmed[(space + 1)..].Trim());
    }

    private static bool LooksLikeEmail(string value) =>
        (value ?? string.Empty).Contains('@', StringComparison.Ordinal);

    private static string FirstNonEmpty(params string[] values)
    {
        for (var i = 0; i < values.Length; i++)
        {
            if (!string.IsNullOrWhiteSpace(values[i]))
            {
                return values[i].Trim();
            }
        }

        return string.Empty;
    }

    private static void Set(string[] row, string header, string value)
    {
        var index = Array.IndexOf(Header, header);
        if (index >= 0)
        {
            row[index] = value ?? string.Empty;
        }
    }

    private static void AppendRow(StringBuilder csv, IReadOnlyList<string> cells)
    {
        for (var i = 0; i < cells.Count; i++)
        {
            if (i > 0)
            {
                csv.Append(',');
            }

            csv.Append(Escape(cells[i]));
        }

        csv.Append("\r\n");
    }

    private static string Escape(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        var needsQuotes = false;
        for (var i = 0; i < value.Length; i++)
        {
            var character = value[i];
            if (character is ',' or '"' or '\r' or '\n')
            {
                needsQuotes = true;
                break;
            }
        }

        if (!needsQuotes)
        {
            return value;
        }

        return "\"" + value.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
    }
}
