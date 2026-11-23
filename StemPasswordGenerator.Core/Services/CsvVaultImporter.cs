using System.Text;
using StemPasswordGenerator.Models;

namespace StemPasswordGenerator.Services;

public sealed class CsvVaultImportResult
{
    public IReadOnlyList<VaultItem> Items { get; init; } = [];

    public int Skipped { get; init; }

    public string Format { get; init; } = string.Empty;

    public string? ErrorKey { get; init; }

    public object[] ErrorArgs { get; init; } = [];

    public bool Success => ErrorKey is null;

    public static CsvVaultImportResult Fail(string key, params object[] args) => new()
    {
        ErrorKey = key,
        ErrorArgs = args
    };
}

public static class CsvVaultImporter
{
    public const int MaximumBytes = 8 * 1024 * 1024;
    public const int MaximumRows = 5000;

    public static CsvVaultImportResult Parse(byte[] data)
    {
        if (data is null || data.Length == 0)
        {
            return CsvVaultImportResult.Fail("CsvEmpty");
        }

        if (data.Length > MaximumBytes)
        {
            return CsvVaultImportResult.Fail("CsvTooLarge", MaximumBytes / (1024 * 1024));
        }

        var text = Decode(data);
        if (string.IsNullOrWhiteSpace(text))
        {
            return CsvVaultImportResult.Fail("CsvEmpty");
        }

        var separator = DetectSeparator(text);
        var rows = CsvTable.Parse(text, separator);
        if (rows.Count < 2)
        {
            return CsvVaultImportResult.Fail("CsvEmpty");
        }

        var headers = MapHeaders(rows[0]);
        if (headers.Count == 0)
        {
            return CsvVaultImportResult.Fail("CsvUnrecognized");
        }

        var format = DetectFormat(headers);
        if (format.Length == 0)
        {
            return CsvVaultImportResult.Fail("CsvUnrecognized");
        }

        var items = new List<VaultItem>();
        var skipped = 0;
        var limit = Math.Min(rows.Count - 1, MaximumRows);
        for (var i = 1; i <= limit; i++)
        {
            var row = rows[i];
            if (IsBlank(row))
            {
                continue;
            }

            var item = format == "bitwarden" ? FromBitwarden(headers, row) : FromGenericLogin(headers, row);
            if (item is null || !CanKeep(item) || IsDuplicate(item, items))
            {
                skipped++;
                continue;
            }

            item.Folder = VaultOrganizer.Normalize(Cell(headers, row, "folder", "group", "collection"));
            items.Add(item);
        }

        skipped += Math.Max(0, rows.Count - 1 - limit);
        if (items.Count == 0)
        {
            return CsvVaultImportResult.Fail("CsvEmpty");
        }

        return new CsvVaultImportResult
        {
            Items = items,
            Skipped = skipped,
            Format = format
        };
    }

    public static bool IsDuplicate(VaultItem candidate, IReadOnlyList<VaultItem> existing)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        ArgumentNullException.ThrowIfNull(existing);
        for (var i = 0; i < existing.Count; i++)
        {
            if (SameRecord(candidate, existing[i]))
            {
                return true;
            }
        }

        return false;
    }

    private static bool SameRecord(VaultItem left, VaultItem right)
    {
        if (!string.Equals(left.Kind, right.Kind, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (!string.Equals(left.Username.Trim(), right.Username.Trim(), StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (left.Kind is VaultItemKind.Note or VaultItemKind.Card or VaultItemKind.Identity)
        {
            return string.Equals(left.Title.Trim(), right.Title.Trim(), StringComparison.OrdinalIgnoreCase);
        }

        if (!string.IsNullOrWhiteSpace(left.Url)
            && !string.IsNullOrWhiteSpace(right.Url)
            && SiteMatchService.HostsMatch(left.Url, right.Url))
        {
            return true;
        }

        return string.Equals(left.Url.Trim(), right.Url.Trim(), StringComparison.OrdinalIgnoreCase)
            && string.Equals(left.Title.Trim(), right.Title.Trim(), StringComparison.OrdinalIgnoreCase);
    }

    private static bool CanKeep(VaultItem item) =>
        VaultItemRules.CanSave(
            item.Kind,
            item.Title,
            item.Password,
            item.AliasEmail,
            item.CardNumber,
            item.Notes,
            item.FullName,
            item.Username);

    private static VaultItem? FromGenericLogin(Dictionary<string, int> headers, IReadOnlyList<string> row)
    {
        var url = Cell(headers, row, "url", "origin_url", "hostname", "website", "web_site", "login_uri");
        var username = Cell(headers, row, "username", "user_name", "email", "login_name", "login_username");
        var password = Cell(headers, row, "password", "login_password");
        var notes = Cell(headers, row, "notes", "note", "comments");
        var totp = Cell(headers, row, "login_totp", "totp", "otpauth", "otp_auth", "one_time_password", "otp");
        var title = TitleFor(Cell(headers, row, "name", "title", "account"), url);
        var parsedTotp = TotpService.TryParseOtpAuth(totp) ?? totp.Trim();
        if (string.IsNullOrWhiteSpace(password) && string.IsNullOrWhiteSpace(parsedTotp))
        {
            return null;
        }

        return new VaultItem
        {
            Kind = VaultItemKind.Login,
            Title = title,
            Url = FirstUri(url),
            Username = username,
            Password = password,
            TotpSecret = parsedTotp,
            Notes = notes
        };
    }

    private static VaultItem? FromBitwarden(Dictionary<string, int> headers, IReadOnlyList<string> row)
    {
        var type = Cell(headers, row, "type").Trim().ToLowerInvariant();
        if (type is "card")
        {
            return FromBitwardenCard(headers, row);
        }

        if (type is "note" or "securenote")
        {
            return FromBitwardenNote(headers, row);
        }

        if (type is "identity")
        {
            return FromBitwardenIdentity(headers, row);
        }

        if (type.Length > 0 && type is not "login")
        {
            return null;
        }

        var url = Cell(headers, row, "login_uri", "uri", "url");
        var username = Cell(headers, row, "login_username", "username");
        var password = Cell(headers, row, "login_password", "password");
        var totp = Cell(headers, row, "login_totp", "totp");
        var notes = Cell(headers, row, "notes", "note");
        var title = TitleFor(Cell(headers, row, "name", "title"), url);
        var parsedTotp = TotpService.TryParseOtpAuth(totp) ?? totp.Trim();
        if (string.IsNullOrWhiteSpace(password) && string.IsNullOrWhiteSpace(parsedTotp))
        {
            return null;
        }

        return new VaultItem
        {
            Kind = VaultItemKind.Login,
            Title = title,
            Url = FirstUri(url),
            Username = username,
            Password = password,
            TotpSecret = parsedTotp,
            Notes = notes
        };
    }

    private static VaultItem FromBitwardenNote(Dictionary<string, int> headers, IReadOnlyList<string> row)
    {
        var title = Cell(headers, row, "name", "title").Trim();
        var notes = Cell(headers, row, "notes", "note").Trim();
        if (title.Length == 0)
        {
            title = UiStrings.Get("KindNote");
        }

        if (notes.Length == 0)
        {
            notes = title;
        }

        return new VaultItem
        {
            Kind = VaultItemKind.Note,
            Title = title,
            Notes = notes
        };
    }

    private static VaultItem? FromBitwardenCard(Dictionary<string, int> headers, IReadOnlyList<string> row)
    {
        var number = Cell(headers, row, "card_number", "cardnumber");
        if (string.IsNullOrWhiteSpace(number))
        {
            return null;
        }

        var title = Cell(headers, row, "name", "title").Trim();
        if (title.Length == 0)
        {
            title = UiStrings.Get("KindCard");
        }

        var month = Cell(headers, row, "card_expmonth", "card_exp_month");
        var year = Cell(headers, row, "card_expyear", "card_exp_year");
        return new VaultItem
        {
            Kind = VaultItemKind.Card,
            Title = title,
            Cardholder = Cell(headers, row, "card_cardholdername", "card_cardholder_name"),
            CardNumber = number.Trim(),
            CardCvv = Cell(headers, row, "card_code", "card_cvv"),
            CardExpiry = FormatExpiry(month, year),
            Notes = Cell(headers, row, "notes", "note")
        };
    }

    private static VaultItem? FromBitwardenIdentity(Dictionary<string, int> headers, IReadOnlyList<string> row)
    {
        var fullName = Join(
            " ",
            Cell(headers, row, "identity_firstname", "identity_first_name"),
            Cell(headers, row, "identity_middlename", "identity_middle_name"),
            Cell(headers, row, "identity_lastname", "identity_last_name"));
        var username = FirstNonEmpty(
            Cell(headers, row, "identity_email"),
            Cell(headers, row, "identity_username"));
        var title = Cell(headers, row, "name", "title").Trim();
        if (title.Length == 0)
        {
            title = fullName.Length > 0 ? fullName : UiStrings.Get("KindIdentity");
        }

        var address = Join(
            ", ",
            Cell(headers, row, "identity_address1"),
            Cell(headers, row, "identity_address2"),
            Cell(headers, row, "identity_city"),
            Cell(headers, row, "identity_state"),
            Cell(headers, row, "identity_postalcode", "identity_postal_code"),
            Cell(headers, row, "identity_country"));

        if (string.IsNullOrWhiteSpace(fullName) && string.IsNullOrWhiteSpace(username))
        {
            return null;
        }

        return new VaultItem
        {
            Kind = VaultItemKind.Identity,
            Title = title,
            FullName = fullName,
            Username = username,
            Phone = Cell(headers, row, "identity_phone"),
            Address = address,
            Notes = Cell(headers, row, "notes", "note")
        };
    }

    private static string FormatExpiry(string month, string year)
    {
        if (string.IsNullOrWhiteSpace(month) && string.IsNullOrWhiteSpace(year))
        {
            return string.Empty;
        }

        var monthPart = month.Trim().PadLeft(2, '0');
        if (monthPart.Length > 2)
        {
            monthPart = monthPart[^2..];
        }

        var yearPart = year.Trim();
        if (yearPart.Length >= 2)
        {
            yearPart = yearPart[^2..];
        }

        return string.IsNullOrWhiteSpace(yearPart) ? monthPart : $"{monthPart}/{yearPart}";
    }

    private static string TitleFor(string name, string url)
    {
        var title = name.Trim();
        if (title.Length > 0)
        {
            return title;
        }

        var host = SiteMatchService.Host(url);
        return host.Length == 0 ? UiStrings.Get("ImportedLoginTitle") : SiteMatchService.DisplayName(url);
    }

    private static string FirstUri(string value)
    {
        var trimmed = value.Trim();
        if (trimmed.Length == 0)
        {
            return string.Empty;
        }

        var split = trimmed.IndexOfAny(['\n', ' ', ',']);
        return split < 0 ? trimmed : trimmed[..split].Trim();
    }

    private static string DetectFormat(Dictionary<string, int> headers)
    {
        if (headers.ContainsKey("login_uri")
            || headers.ContainsKey("login_username")
            || headers.ContainsKey("login_password")
            || (headers.ContainsKey("type") && (headers.ContainsKey("folder") || headers.ContainsKey("favorite"))))
        {
            return "bitwarden";
        }

        if (headers.ContainsKey("group")
            || headers.ContainsKey("account")
            || headers.ContainsKey("login_name")
            || headers.ContainsKey("web_site"))
        {
            return "keepass";
        }

        if (headers.ContainsKey("one_time_password")
            || headers.ContainsKey("otpauth")
            || headers.ContainsKey("otp_auth")
            || (headers.ContainsKey("website") && headers.ContainsKey("title") && !headers.ContainsKey("name")))
        {
            return "onepassword";
        }

        if (headers.ContainsKey("formactionorigin")
            || headers.ContainsKey("form_action_origin")
            || headers.ContainsKey("httprealm")
            || headers.ContainsKey("http_realm"))
        {
            return "firefox";
        }

        if (headers.ContainsKey("url")
            || headers.ContainsKey("origin_url")
            || headers.ContainsKey("hostname")
            || (headers.ContainsKey("username") && headers.ContainsKey("password")))
        {
            return "chromium";
        }

        return string.Empty;
    }

    private static Dictionary<string, int> MapHeaders(IReadOnlyList<string> headerRow)
    {
        var map = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i < headerRow.Count; i++)
        {
            var key = NormalizeHeader(headerRow[i]);
            if (key.Length == 0 || map.ContainsKey(key))
            {
                continue;
            }

            map[key] = i;
        }

        return map;
    }

    private static string NormalizeHeader(string header)
    {
        var trimmed = header.Trim().TrimStart('\uFEFF').ToLowerInvariant();
        if (trimmed.Length == 0)
        {
            return string.Empty;
        }

        var builder = new StringBuilder(trimmed.Length);
        for (var i = 0; i < trimmed.Length; i++)
        {
            var character = trimmed[i];
            builder.Append(character is ' ' or '-' ? '_' : character);
        }

        return builder.ToString();
    }

    private static string Cell(Dictionary<string, int> headers, IReadOnlyList<string> row, params string[] names)
    {
        for (var i = 0; i < names.Length; i++)
        {
            if (headers.TryGetValue(names[i], out var index) && index >= 0 && index < row.Count)
            {
                return row[index].Trim();
            }
        }

        return string.Empty;
    }

    private static bool IsBlank(IReadOnlyList<string> row)
    {
        for (var i = 0; i < row.Count; i++)
        {
            if (!string.IsNullOrWhiteSpace(row[i]))
            {
                return false;
            }
        }

        return true;
    }

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

    private static string Join(string separator, params string[] parts)
    {
        var builder = new StringBuilder();
        for (var i = 0; i < parts.Length; i++)
        {
            var part = parts[i].Trim();
            if (part.Length == 0)
            {
                continue;
            }

            if (builder.Length > 0)
            {
                builder.Append(separator);
            }

            builder.Append(part);
        }

        return builder.ToString();
    }

    private static char DetectSeparator(string text)
    {
        var lineEnd = text.IndexOfAny(['\r', '\n']);
        var header = lineEnd < 0 ? text : text[..lineEnd];
        var commas = CountUnquoted(header, ',');
        var semis = CountUnquoted(header, ';');
        return semis > commas ? ';' : ',';
    }

    private static int CountUnquoted(string text, char separator)
    {
        var count = 0;
        var quoted = false;
        for (var i = 0; i < text.Length; i++)
        {
            var character = text[i];
            if (character == '"')
            {
                quoted = !quoted;
            }
            else if (!quoted && character == separator)
            {
                count++;
            }
        }

        return count;
    }

    private static string Decode(byte[] data)
    {
        if (data.Length >= 2 && data[0] == 0xFF && data[1] == 0xFE)
        {
            return Encoding.Unicode.GetString(data, 2, data.Length - 2);
        }

        if (data.Length >= 2 && data[0] == 0xFE && data[1] == 0xFF)
        {
            return Encoding.BigEndianUnicode.GetString(data, 2, data.Length - 2);
        }

        var offset = data.Length >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF ? 3 : 0;
        return Encoding.UTF8.GetString(data, offset, data.Length - offset);
    }

    private static class CsvTable
    {
        public static List<List<string>> Parse(string text, char separator)
        {
            var rows = new List<List<string>>();
            var row = new List<string>();
            var field = new StringBuilder();
            var quoted = false;
            for (var i = 0; i < text.Length; i++)
            {
                var character = text[i];
                if (quoted)
                {
                    if (character == '"')
                    {
                        if (i + 1 < text.Length && text[i + 1] == '"')
                        {
                            field.Append('"');
                            i++;
                        }
                        else
                        {
                            quoted = false;
                        }
                    }
                    else
                    {
                        field.Append(character);
                    }

                    continue;
                }

                if (character == '"')
                {
                    quoted = true;
                    continue;
                }

                if (character == separator)
                {
                    row.Add(field.ToString());
                    field.Clear();
                    continue;
                }

                if (character == '\r')
                {
                    if (i + 1 < text.Length && text[i + 1] == '\n')
                    {
                        i++;
                    }

                    FinishRow(rows, row, field);
                    continue;
                }

                if (character == '\n')
                {
                    FinishRow(rows, row, field);
                    continue;
                }

                field.Append(character);
            }

            if (field.Length > 0 || row.Count > 0)
            {
                FinishRow(rows, row, field);
            }

            return rows;
        }

        private static void FinishRow(List<List<string>> rows, List<string> row, StringBuilder field)
        {
            row.Add(field.ToString());
            field.Clear();
            rows.Add([.. row]);
            row.Clear();
        }
    }
}
