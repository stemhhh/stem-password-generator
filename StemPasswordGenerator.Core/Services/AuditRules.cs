using System.Text;
using System.Text.Json;
using StemPasswordGenerator.Models;

namespace StemPasswordGenerator.Services;

public static class AuditRules
{
    public const int MaximumEvents = 400;
    public const int MaximumPending = 80;
    public const int MaximumTitleLength = 80;

    private static readonly HashSet<string> AllowedKinds = new(StringComparer.Ordinal)
    {
        AuditKind.UnlockFail,
        AuditKind.UnlockOk,
        AuditKind.Used,
        AuditKind.Created,
        AuditKind.Updated,
        AuditKind.Deleted,
        AuditKind.PasswordChanged,
        AuditKind.Imported,
        AuditKind.MediaAdded,
        AuditKind.MediaExported
    };

    private static readonly HashSet<string> AllowedMethods = new(StringComparer.Ordinal)
    {
        AuditMethod.Master,
        AuditMethod.Hello,
        AuditMethod.HelloCancel,
        AuditMethod.Usb,
        AuditMethod.Recovery,
        AuditMethod.Human,
        AuditMethod.Copy,
        AuditMethod.Autofill,
        AuditMethod.Export,
        string.Empty
    };

    public static AuditEvent Sanitize(AuditEvent? source)
    {
        var utc = source?.Utc ?? default;
        if (utc == default)
        {
            utc = DateTimeOffset.UtcNow;
        }

        var kind = AllowedKinds.Contains(source?.Kind ?? string.Empty)
            ? source!.Kind
            : AuditKind.Used;
        var method = AllowedMethods.Contains(source?.Method ?? string.Empty)
            ? source!.Method
            : string.Empty;
        var title = kind == AuditKind.UnlockFail
            ? string.Empty
            : TrimTitle(source?.Title);
        var itemKind = kind == AuditKind.UnlockFail
            ? string.Empty
            : TrimTitle(source?.ItemKind);
        Guid? itemId = kind == AuditKind.UnlockFail ? null : source?.ItemId;

        return new AuditEvent
        {
            Utc = utc.ToUniversalTime(),
            Kind = kind,
            Method = method,
            Title = title,
            ItemKind = itemKind,
            ItemId = itemId is { } id && id != Guid.Empty ? id : null
        };
    }

    public static void Append(List<AuditEvent> events, AuditEvent incoming, int maximum = MaximumEvents)
    {
        ArgumentNullException.ThrowIfNull(events);
        events.Add(Sanitize(incoming));
        Trim(events, maximum);
    }

    public static void AppendFail(List<AuditEvent> events, DateTimeOffset utc, string method)
    {
        Append(events, new AuditEvent
        {
            Utc = utc,
            Kind = AuditKind.UnlockFail,
            Method = method
        }, MaximumPending);
    }

    public static void Merge(List<AuditEvent> destination, IEnumerable<AuditEvent> incoming)
    {
        ArgumentNullException.ThrowIfNull(destination);
        ArgumentNullException.ThrowIfNull(incoming);
        foreach (var item in incoming)
        {
            destination.Add(Sanitize(item));
        }

        destination.Sort(static (left, right) => left.Utc.CompareTo(right.Utc));
        Trim(destination, MaximumEvents);
    }

    public static bool InBucket(AuditEvent item, string? bucket)
    {
        ArgumentNullException.ThrowIfNull(item);
        var key = string.IsNullOrWhiteSpace(bucket) ? AuditBucket.All : bucket;
        return key switch
        {
            AuditBucket.Fail => item.Kind == AuditKind.UnlockFail,
            AuditBucket.Use => item.Kind is AuditKind.Used or AuditKind.UnlockOk,
            AuditBucket.Entry => item.Kind is AuditKind.Created or AuditKind.Updated or AuditKind.Deleted
                or AuditKind.PasswordChanged or AuditKind.Imported or AuditKind.MediaAdded or AuditKind.MediaExported,
            _ => true
        };
    }

    public static bool Matches(AuditEvent item, string query)
    {
        ArgumentNullException.ThrowIfNull(item);
        if (string.IsNullOrWhiteSpace(query))
        {
            return true;
        }

        return Headline(item).Contains(query, StringComparison.OrdinalIgnoreCase)
            || Detail(item).Contains(query, StringComparison.OrdinalIgnoreCase)
            || item.Title.Contains(query, StringComparison.OrdinalIgnoreCase)
            || item.Kind.Contains(query, StringComparison.OrdinalIgnoreCase)
            || item.Method.Contains(query, StringComparison.OrdinalIgnoreCase);
    }

    public static string Headline(AuditEvent item)
    {
        ArgumentNullException.ThrowIfNull(item);
        if (item.Kind == AuditKind.UnlockFail)
        {
            return item.Method switch
            {
                AuditMethod.Hello => UiStrings.Get("AuditFailHello"),
                AuditMethod.HelloCancel => UiStrings.Get("AuditFailHelloCancel"),
                AuditMethod.Usb => UiStrings.Get("AuditFailUsb"),
                AuditMethod.Recovery => UiStrings.Get("AuditFailRecovery"),
                AuditMethod.Human => UiStrings.Get("AuditFailHuman"),
                _ => UiStrings.Get("AuditFailMaster")
            };
        }

        return item.Kind switch
        {
            AuditKind.UnlockOk => UiStrings.Get("AuditUnlockOk"),
            AuditKind.Used when item.Method == AuditMethod.Autofill => UiStrings.Get("AuditUsedAutofill"),
            AuditKind.Used when item.Method == AuditMethod.Export => UiStrings.Get("AuditUsedExport"),
            AuditKind.Used => UiStrings.Get("AuditUsedCopy"),
            AuditKind.Created => UiStrings.Get("AuditCreated"),
            AuditKind.Updated => UiStrings.Get("AuditUpdated"),
            AuditKind.Deleted => UiStrings.Get("AuditDeleted"),
            AuditKind.PasswordChanged => UiStrings.Get("AuditPasswordChanged"),
            AuditKind.Imported => UiStrings.Get("AuditImported"),
            AuditKind.MediaAdded => UiStrings.Get("AuditMediaAdded"),
            AuditKind.MediaExported => UiStrings.Get("AuditMediaExported"),
            _ => UiStrings.Get("AuditUsedCopy")
        };
    }

    public static string Detail(AuditEvent item)
    {
        ArgumentNullException.ThrowIfNull(item);
        var method = MethodLabel(item.Method);
        if (item.Kind == AuditKind.Imported && int.TryParse(item.Title, out var count) && count >= 0)
        {
            var imported = UiStrings.Format("AuditImportedCount", count);
            return string.IsNullOrEmpty(method) ? imported : imported + " · " + method;
        }

        if (string.IsNullOrEmpty(item.Title))
        {
            return method;
        }

        var titled = UiStrings.Format("AuditOnItem", item.Title);
        return string.IsNullOrEmpty(method) ? titled : titled + " · " + method;
    }

    public static byte[] ToUtf8(IReadOnlyList<AuditEvent> events)
    {
        var safe = events.Select(Sanitize).ToList();
        return JsonSerializer.SerializeToUtf8Bytes(safe, VaultJsonContext.Default.ListAuditEvent);
    }

    public static List<AuditEvent> FromUtf8(byte[]? utf8)
    {
        if (utf8 is null || utf8.Length == 0)
        {
            return [];
        }

        try
        {
            var parsed = JsonSerializer.Deserialize(utf8, VaultJsonContext.Default.ListAuditEvent) ?? [];
            var list = parsed.Select(Sanitize).ToList();
            Trim(list, MaximumPending);
            return list;
        }
        catch (JsonException)
        {
            return [];
        }
    }

    public static bool JsonLooksSafe(ReadOnlySpan<byte> utf8)
    {
        var text = Encoding.UTF8.GetString(utf8);
        return !text.Contains("\"password\"", StringComparison.OrdinalIgnoreCase)
            && !text.Contains("\"totpSecret\"", StringComparison.OrdinalIgnoreCase)
            && !text.Contains("\"cardCvv\"", StringComparison.OrdinalIgnoreCase)
            && !text.Contains("\"notes\"", StringComparison.OrdinalIgnoreCase);
    }

    private static string MethodLabel(string method) => method switch
    {
        AuditMethod.Master => UiStrings.Get("AuditMethodMaster"),
        AuditMethod.Hello => UiStrings.Get("AuditMethodHello"),
        AuditMethod.HelloCancel => UiStrings.Get("AuditMethodHello"),
        AuditMethod.Usb => UiStrings.Get("AuditMethodUsb"),
        AuditMethod.Recovery => UiStrings.Get("AuditMethodRecovery"),
        AuditMethod.Human => UiStrings.Get("AuditMethodHuman"),
        AuditMethod.Copy => UiStrings.Get("AuditMethodCopy"),
        AuditMethod.Autofill => UiStrings.Get("AuditMethodAutofill"),
        AuditMethod.Export => UiStrings.Get("AuditMethodExport"),
        _ => string.Empty
    };

    private static string TrimTitle(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var builder = new StringBuilder(Math.Min(value.Length, MaximumTitleLength));
        foreach (var character in value.Trim())
        {
            if (char.IsControl(character))
            {
                continue;
            }

            builder.Append(character);
            if (builder.Length >= MaximumTitleLength)
            {
                break;
            }
        }

        return builder.ToString();
    }

    private static void Trim(List<AuditEvent> events, int maximum)
    {
        if (events.Count <= maximum)
        {
            return;
        }

        events.RemoveRange(0, events.Count - maximum);
    }
}
