using StemPasswordGenerator.Services;

namespace StemPasswordGenerator.Models;

public sealed class AuditRow
{
    public AuditRow(AuditEvent source)
    {
        Source = AuditRules.Sanitize(source);
        WhenLabel = ItemUsage.FormatLocalDateTime(Source.Utc);
        Headline = AuditRules.Headline(Source);
        Detail = AuditRules.Detail(Source);
    }

    public AuditEvent Source { get; }

    public string WhenLabel { get; }

    public string Headline { get; }

    public string Detail { get; }
}
